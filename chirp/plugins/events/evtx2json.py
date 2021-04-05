"""
Script to convert evtx_dump.py XML output (https://github.com/williballenthin/python-evtx)
to JSON and optionally, push events to Splunk via HTTP Event Collector (pip install splunk-hec-handler)

Process file(s)
    evtx2json.py process_files --files file1.evtx file2.evtx folder/*.evtx

Process folder
    evtx2json.py process_folder --folder evtx_folder

Enable logging to Splunk
    evtx2json.py --splunk --host splunkfw.domain.tld --port 8888 --token BEA33046C-6FEC-4DC0-AC66-4326E58B54C3 \
        process_files -f samples/*.evtx

Enable logging to Splunk but disable JSON modifications
    evtx2json.py --splunk --host splunkfw.domain.tld --port 8888 --token BEA33046C-6FEC-4DC0-AC66-4326E58B54C3 \
        --disable_json_tweaks process_files -f samples/*.evtx

"""

# flake8: noqa

# Standard Python Libraries
import argparse
from glob import glob
import json
import logging
import os.path
import sys
import time
import xml.etree.ElementTree as ET  # nosec

# Third-Party Libraries
import Evtx.Evtx as evtx
from xmljson import badgerfish as bf

logger = logging.getLogger()

# Additional fields for Splunk indexing
fields = dict({})

global event_counter, error_counter


def add_splunk_handler(args):
    """
    Add remote Splunk HEC logging handler to logger
    :param args:  argparse Namespace containing values to configure Splunk handler.  Host and Token required.
    :return: None.  Adds splunk log handler to logger.
    """
    if not args.splunk:
        return
    try:
        # Third-Party Libraries
        from splunk_hec_handler import SplunkHecHandler
    except ModuleNotFoundError as err:
        logger.warning(
            "Filed to import 'splunk_hec_handler' python module.  Try 'pip install splunk_hec_handler'"
        )

    except Exception as err:
        logger.warning(
            "Error encountered adding Splunk logging handler.  Error: %s" % err
        )

    else:
        if not args.verify:
            try:
                # Third-Party Libraries
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ModuleNotFoundError as err:
                logger.debug("Failed to suppress SSL warnings")

        logger.debug(
            "Configuring Splunk handler: host: %s, port: %d, proto: %s, ssl_verify: %s, token: %s, source: %s, sourcetype: %s"
            % (
                args.host,
                args.port,
                args.proto,
                args.verify,
                args.token,
                args.source,
                args.sourcetype,
            )
        )

        splunk_handler = SplunkHecHandler(
            args.host,
            args.token,
            index=args.index,
            port=args.port,
            proto=args.proto,
            ssl_verify=args.verify,
            source=args.source,
            sourcetype=args.sourcetype,
        )
        splunk_handler.setLevel(logging.getLevelName(args.loglevel))
        logger.addHandler(splunk_handler)


def remove_namespace(tree):
    """
    Namespace can make Splunk output ugly.  This function removes namespace from all elements
    e.g element.tag = '{http://schemas.microsoft.com/win/2004/08/events/event}System'
    :param tree: xml ElementTree Element
    :return: xml ElementTree Element with namespace removed
    """
    # Remove namespace
    for element in tree.getiterator():
        try:
            if element.tag.startswith("{"):
                element.tag = element.tag.split("}")[1]
        except:
            pass

    return tree


def xml2json(xml_str):
    """
    Convert string xml (after striping namespace) output from evtx.Evtx to XML tree object
    :param xml_str: string
    :return: xml ElementTree Element
    """
    try:
        tree = remove_namespace(ET.fromstring(str(xml_str)))
        obj = bf.data(tree)
    except:
        # logger.error("Failed to convert XML to JSON for %s" % xml_str)
        pass
    else:
        return obj


def iter_evtx2xml(evtx_file):
    """
    Generator function to read events from evtx file and convert to xml
    :param evtx_file: file path string
    :return: generator to xml string representation of evtx event
    """
    global error_counter, event_counter
    error_counter = 0
    event_counter = 0
    try:
        with evtx.Evtx(evtx_file) as log:
            # process each log entry and return xml representation
            for record in log.records():
                event_counter += 1
                try:
                    yield record.xml()
                except Exception as err:
                    error_counter += 1
                    # logger.error("Failed to convert EVTX to XML for %s. Error count: %d" % (evtx_file, error_counter))
    except Exception as err:
        raise
    if error_counter:
        logging.error("Failed to read {} events.".format(error_counter))


def _transform_system(output):
    # xmljson output of System field is rather unruly Event{System{1{}...n{}}}
    # This function cleans up the System section for easier Splunking.
    try:
        systemdata = output["Event"]["System"]
        new_systemdata = {}
    except KeyError:
        logger.debug('Missing "System" section. Skipping.')
    else:
        for k, v in systemdata.items():
            if hasattr(v, "items") and len(v) == 1 and "$" in v.keys():
                new_systemdata[k] = v["$"]
            else:
                new_systemdata[k] = v

        _ = output["Event"].pop("System")
        output["Event"]["System"] = {}
        output["Event"]["System"].update(new_systemdata)
    finally:
        return output


def _transform_eventdata(output):
    # xmljson output of EventData field is rather unruly Event{EventData{ Data[1{}...n{}] }}
    # This function cleans up the EventData section for easier Splunking.
    try:
        eventdata = output["Event"]["EventData"]
    except:
        logger.debug('Missing "EventData" section. Skipping.')
    else:
        new_eventdata = {}
        for data in eventdata["Data"]:
            if "@Name" in data.keys() and "$" in data.keys():
                new_eventdata[data["@Name"]] = data["$"]
            elif "@Name" in data.keys() and "$" not in data.keys():
                new_eventdata[data["@Name"]] = None
            else:
                new_eventdata.extend(data)
        _ = output["Event"].pop("EventData")
        output["Event"]["EventData"] = {}
        output["Event"]["EventData"].update(new_eventdata)
    finally:
        return output


def splunkify(output, source):
    """
    Any customization to the final splunk output goes here
    :param output: JSON obj returned by xml2json
    :param source: str. evtx source
    :return: JSON obj with Splunk customizations
    """

    event = _transform_system(output)
    event = _transform_eventdata(event)

    # Custom fields for Splunk processing
    event["Event"]["fields"] = {}

    # Set Splunk event _time to timestamp in the evtx event.
    try:
        _ts = event["Event"]["System"]["TimeCreated"]["@SystemTime"]
        try:
            _ts = time.mktime(time.strptime(_ts.strip(), "%Y-%m-%d %H:%M:%S.%f"))
        except ValueError:
            _ts = time.mktime(time.strptime(_ts.strip(), "%Y-%m-%d %H:%M:%S"))
    except KeyError:
        logger.warning("Event missing TimeCreated field")
        _ts = time.time()
    except ValueError:
        logger.warning("Failed to convert TimeCreated (%s) to epoch timestamp" % _ts)
        _ts = time.time()
    else:
        # example evtx timestamp '2016-07-01 11:05:48.162424'
        event["Event"]["fields"]["time"] = _ts

    # Set host field to Computer names in the evtx event
    try:
        _host = event["Event"]["System"]["Computer"]
    except KeyError:
        logger.warning("Event missing Computer field")
    else:
        event["Event"]["fields"]["host"] = _host

    # Set source field to name of the evtx file
    event["Event"]["fields"]["source"] = os.path.basename(source)

    return event


def output_stats(evtx_file, success_counter, start_time):
    """ Log basic stats per evtx file """
    global event_counter, error_counter
    delta_secs = int(time.time()) - start_time

    logger.info(
        {
            "file": evtx_file,
            "total_events": event_counter,
            "pass": success_counter,
            "fail": error_counter,
            "time": start_time,
            "elapsed_sec": delta_secs,
        }
    )


def process_files(args):
    """
    Each evtx file is first converted to xml using python-evtx module
    Next, the xml output is converted to JSON using xmljson (badgerfish)
    Finally, the JSON output is customized, unless --disable_json_tweaks is specified as a flag
    If --splunk flag is specified, events are logged to the specified Splunk host (--host)
    """
    if args.splunk:
        add_splunk_handler(args)

    global error_counter
    start_time = int(time.time())
    for evtx_file in args.files:
        if evtx_file.endswith(".evtx"):
            logger.debug("Now processing %s" % evtx_file)
            success_counter = 0
            for xml_str in iter_evtx2xml(evtx_file):
                try:
                    if args.disable_json_tweaks:
                        output = xml2json(xml_str)
                    else:
                        output = splunkify(xml2json(xml_str), evtx_file)
                except Exception:
                    error_counter += 1
                else:
                    logger.info(json.loads(json.dumps(output["Event"])))
                    success_counter += 1

            output_stats(evtx_file, success_counter, start_time)


def process_folder(args):
    files = glob(os.path.join(args.folder, "*.evtx"))
    args.__setattr__("files", files)
    process_files(args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        add_help=False, description="Convert Windows evtx files to JSON"
    )
    parser.add_argument("--help", "-h", help="This help message.", action="help")
    parser.add_argument(
        "--loglevel",
        "-v",
        help="Log level",
        choices=[0, 10, 20, 30, 40, 50],
        default=20,
        type=int,
    )
    parser.add_argument(
        "--disable_json_tweaks",
        help="Skip customization to time, host, source etc. json fields",
        required=False,
        default=False,
        action="store_true",
    )
    subparsers = parser.add_subparsers()

    splunk_parser_group = parser.add_argument_group(
        title="Splunk Integration", description="Send JSON output to Splunk"
    )
    splunk_parser_group.add_argument(
        "--splunk",
        help="Send JSON output to Splunk",
        required=False,
        default=False,
        action="store_true",
    )
    splunk_parser_group.add_argument(
        "--host", help="Splunk host with HEC listener", default="localhost"
    )
    splunk_parser_group.add_argument("--token", help="HEC Token")
    splunk_parser_group.add_argument(
        "--port",
        help="Splunk HEC listener port",
        type=int,
        required=False,
        default=8008,
    )
    splunk_parser_group.add_argument(
        "--proto",
        help="Splunk HEC protocol",
        default="https",
        required=False,
        choices=["http", "https"],
    )
    splunk_parser_group.add_argument("--index", help="Splunk Index", required=False)
    splunk_parser_group.add_argument(
        "--source",
        help="Event Source.  NOTE: Computer name in evtx will overwrite this value",
        default=os.path.basename(sys.argv[0]),
        required=False,
    )
    splunk_parser_group.add_argument(
        "--sourcetype", help="Event Sourcetype", default="_json", required=False
    )
    splunk_parser_group.add_argument(
        "--verify",
        help="SSL certificate verification",
        default=False,
        required=False,
        action="store_true",
    )

    # Parser for single evtx file
    parser_fh = subparsers.add_parser("process_files")
    fh_parser_group = parser_fh.add_argument_group(title="Process evtx files")
    fh_parser_group.add_argument(
        "--files", "-f", help="evtx file", nargs="+", required=True
    )
    fh_parser_group.set_defaults(func=process_files)

    # Parser for folder containing evtx files
    parser_fh = subparsers.add_parser("process_folder")
    folder_parser_group = parser_fh.add_argument_group(
        title="Process folder containing evtx files"
    )
    folder_parser_group.add_argument(
        "--folder", help="Folder containing evtx files", required=True
    )
    folder_parser_group.set_defaults(func=process_folder)

    args = parser.parse_args()
    try:
        stream_handler.setLevel(logging.getLevelName(args.loglevel))
        args.func(args)
    except Exception as err:
        print("Error: %s\n" % err)
        parser.print_help()

#  Copyright 2022-2023 VMware, Inc.
#  SPDX-License-Identifier: Apache-2.0
import sys
from typing import List

import aria.ops.adapter_logging as logging # type: ignore
import xml.etree.ElementTree as ET
from aria.ops.adapter_instance import AdapterInstance # type: ignore
from aria.ops.definition.adapter_definition import AdapterDefinition # type: ignore
from aria.ops.result import CollectResult # type: ignore
from aria.ops.result import EndpointResult # type: ignore
from aria.ops.result import TestResult # type: ignore
from aria.ops.timer import Timer # type: ignore
from ssltlsChecker import process_endpoint
from constants import ADAPTER_KIND
from constants import ADAPTER_NAME
# TODO: Remove after tesing localy
import os
import tempfile
import re

logger = logging.getLogger(__name__)


def get_adapter_definition() -> AdapterDefinition:
    with Timer(logger, "Get Adapter Definition"):
        definition = AdapterDefinition(ADAPTER_KIND, ADAPTER_NAME)

        # Will be advanced config
        definition.define_string_parameter(
            "https_endpoints",
            label="List of SSL/TLS secured endpoints",
            description="Enter the configuration file name that contains the list of SSL/TLS secured endpoints to connect to.",
            default="ssltls_endpoints",
            required=True,
        )

        definition.define_int_parameter(
            "container_memory_limit",
            label="Adapter Memory Limit (MB)",
            description="Sets the maximum amount of memory VMware Aria Operations can "
            "allocate to the container running this adapter instance.",
            required=True,
            advanced=True,
            default=1024,
        )

        # Object definitions and their metrics/properties
        httpsWorld_instance = definition.define_object_type(
            "httpsWorld_resource_kind", "SSL-TLS World")

        httpsEndpoint_instance = definition.define_object_type(
            "httpsEndpoint_resource_kind", "SSL-TLS Endpoint")

        httpsEndpoint_instance.define_metric(
            "remainig_days", "Days until expiry")

        httpsEndpoint_instance.define_metric(
            "cypher_bits", "Cipher bits")

        httpsEndpoint_instance.define_string_property(
            "negotiated_protocol", "Negotiated protocol")
        
        httpsEndpoint_instance.define_string_property(
            "protocol_family", "Protocol family")
        
        httpsEndpoint_instance.define_string_property(
            "cipher_suite", "Cipher suite")
        
        httpsEndpoint_instance.define_string_property(
            "cipher_protocol_label", "Cipher protocol label")

        httpsEndpoint_instance.define_string_property(
            "certificate_expires", "Certificate expires")
        
        httpsEndpoint_instance.define_string_property(
            "certificate_subject", "Certificate subject")
        
        httpsEndpoint_instance.define_string_property(
            "certificate_issuer", "Certificate issuer")

        logger.debug(f"Returning adapter definition: {definition.to_json()}")
        return definition

def httpsEndpoints_configFile(adapter_instance: AdapterInstance) -> str:
    httpsEndpoints_config_file = adapter_instance.get_identifier_value("https_endpoints")
    return httpsEndpoints_config_file

def get_config_file_data(adapter_instance: AdapterInstance, configFile) -> str:
    apiPath = f"api/configurations/files?path=SolutionConfig/{configFile}"
    logger.debug("apiPath: ")
    logger.debug(apiPath)
    with adapter_instance.suite_api_client as suite_api:
        getConfigFile = suite_api.get(url = apiPath)
    if getConfigFile.ok:
        lines = getConfigFile.text
        parsedResponse = ET.fromstring(lines)
        formattedLines = parsedResponse.text.strip().split(',')
        objectList = []
        for line in formattedLines:
            objectList.append(line.strip())
        return objectList

def test(adapter_instance: AdapterInstance) -> TestResult:
    with Timer(logger, "Test"):
        result = TestResult()
        try:
            # TODO: Add connection testing logic
            pass  # TODO: Remove pass statement

        except Exception as e:
            logger.error("Unexpected connection test error")
            logger.exception(e)
            result.with_error("Unexpected connection test error: " + repr(e))
        finally:
            # TODO: If any connections are still open, make sure they are closed before returning
            logger.debug(f"Returning test result: {result.get_json()}")
            return result


def collect(adapter_instance: AdapterInstance) -> CollectResult:
    with Timer(logger, "Collection"):
        result = CollectResult()
        try:
            ssltls_world = result.object(
                        ADAPTER_KIND, "httpsWorld_resource_kind", "SSL-TLS-World")
            result.add_object(ssltls_world)
            httpEndpointsConfigFile = httpsEndpoints_configFile(adapter_instance)
            # Use provided name, append .xml if needed
            filename = httpEndpointsConfigFile if httpEndpointsConfigFile.endswith(".xml") else f"{httpEndpointsConfigFile}.xml"
            httpEndpoints = get_config_file_data(adapter_instance, filename)
            
            """
            # Use a writable temporary directory instead of the current working directory
            preferred_dir = tempfile.gettempdir()
            created_path = os.path.join(preferred_dir, filename)
            # Write a simple XML wrapper with the specified endpoints in the element text
            xml_content = (
                "www.thomas-kopton.de:443,\n"
                "www.yahoo.de:443\n"httpEndpointsConfigFile
            )
            try:
                with open(created_path, "w", encoding="utf-8") as fh:
                    fh.write(xml_content)
                logger.info(f"Created config file at: {created_path}")
            except Exception as e:
                logger.error(f"Unable to create config file at {preferred_dir}: {e}")

            # Read and parse the created config file
            httpEndpoints = []
            try:
                with open(created_path, "r", encoding="utf-8") as fh:
                    raw = fh.read()
                logger.info(f"Config file raw content: {raw!r}")
                # Split on commas and any whitespace/newlines, then strip and filter empties
                parts = re.split(r'[,\s]+', raw)
                httpEndpoints = [p.strip() for p in parts if p.strip()]
            except Exception as e:
                logger.error(f"Error reading local config file {created_path}: {e}")
                httpEndpoints = []
            """

            for endpoint in httpEndpoints:
                logger.info(f"Processing endpoint: {endpoint}")
                process_endpoint(result, endpoint, ssltls_world)

        except Exception as e:
            logger.error("Unexpected collection error")
            logger.exception(e)
            result.with_error("Unexpected collection error: " + repr(e))
        finally:
            # TODO: If any connections are still open, make sure they are closed before returning
            logger.debug(f"Returning collection result {result.get_json()}")
            return result


def get_endpoints(adapter_instance: AdapterInstance) -> EndpointResult:
    with Timer(logger, "Get Endpoints"):
        result = EndpointResult()
        # TODO: Add any additional endpoints if any

        logger.debug(f"Returning endpoints: {result.get_json()}")
        return result


# Main entry point of the adapter. You should not need to modify anything below this line.
def main(argv: List[str]) -> None:
    logging.setup_logging("adapter.log")
    logging.rotate()
    logger.info(f"Running adapter code with arguments: {argv}")
    if len(argv) != 3:
        logger.error("Arguments must be <method> <inputfile> <ouputfile>")
        sys.exit(1)

    method = argv[0]
    try:
        if method == "test":
            test(AdapterInstance.from_input()).send_results()
        elif method == "endpoint_urls":
            get_endpoints(AdapterInstance.from_input()).send_results()
        elif method == "collect":
            collect(AdapterInstance.from_input()).send_results()
        elif method == "adapter_definition":
            result = get_adapter_definition()
            if type(result) is AdapterDefinition:
                result.send_results()
            else:
                logger.info(
                    "get_adapter_definition method did not return an AdapterDefinition"
                )
                sys.exit(1)
        else:
            logger.error(f"Command {method} not found")
            sys.exit(1)
    finally:
        logger.info(Timer.graph())
        sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])

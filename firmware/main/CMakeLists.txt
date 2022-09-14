idf_component_register(SRCS "main.c" 
                            "can4vscp.c" 
                            "websrv.c" 
                            "improv.cpp" 
                            "tcpsrv.c" 
                            "udpsrv.c" 
                            "udpclient.c"
                            "~/development/VSCP/vscp-firmware/common/vscp-link-protocol.c"
                            "~/development/VSCP/vscp-firmware/common/vscp-fifo.c"
                            "~/development/VSCP/vscp-firmware/common/vscp-firmware-helper.c"

                    INCLUDE_DIRS "." 
                                  "~/development/VSCP/vscp-firmware/common/")

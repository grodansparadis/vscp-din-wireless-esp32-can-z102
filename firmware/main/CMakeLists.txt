idf_component_register(SRCS "main.c"
                            "mqtt.c" 
                            "websrv.c"  
                            "can4vscp.c"                             
                            "improv.cpp" 
                            "tcpsrv.c" 
                            "callbacks-link.c"
                            "callbacks-vscp-protocol.c"
                            "../third_party/vscp-firmware/common/vscp-link-protocol.c"
                            "../third_party/vscp-firmware/common/vscp-firmware-helper.c"

                    INCLUDE_DIRS "." 
                                  "../third_party/vscp-firmware/common/")

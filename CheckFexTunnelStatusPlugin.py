from CustomMetricPlugin import CustomMetricPlugin

class TJXFexTunnelStatusPlugin(CustomMetricPlugin):

    # This textkey identifies the plugin, not individual metric types.  It should be
    # of the form "com.example.sample" which uniquely identifies your organization and
    # the purpose of the plugin
    textkey = "com.fortinet.fortigate"

    # This is the name of the plugin, which will be used when displaying metric
    # options supported by the plugin.
    name = "FexTunnelStatus"

    def get_metadata(self):
        """
        Builds a list of information about the metrics that this plugin is able to collect.

        Returns a list of dictionaries, each with the following keys:
        - metric_textkey - unique textkey that identifies this metric type within the plugin
        - name - human-friendly name for the metric, displayed in config UIs, graphs and alerts
        - description - human friendly description of the metric, displayed as supporting
          content when configuring the metric
        - unit - string which specifies the unit of the metric, or None if unit-less
        """
        
        return [
            {
                "metric_textkey": "fext_tunnel_status",
                "name": "FortiExtender Tunnel Status",
                "description": "IPSec overlay tunnels bound to FortiExtender",
                "unit": "status",
                "resource_options": None,
            },
        ]

    def get_data(self, textkey, option, instance_id, hostname, device_type,
                 device_sub_type, tags, attributes):
        """
        Gather data for a specific metric specified by the textkey argument.

        textkey identifies the specific metric type that should be gathered.

        option is the (optional) specifier for a specific instance of the metric, for
        example indicating what port on a switch to check.  If not specified in the central
        configuration it will have a value of None

        Passes the following items that can be used by the plugin:
        - instance_id - the global ID of the target instance that aligns with what is
          present in the control panel or FortiMonitor API
        - hostname - the IP or FQDN of the target instance
        - device_type, device_sub_type - strings which specify the type of the instance
        - tags - list of strings with each tag that's applied to the instance
        - attributes - dictionary of attribute keys and values that have been applied to the instance

        Returns either a floating point metric value or None if no value is available
        """
        
        try:
            fex_tunnel_status = self.fortiapi_fortios(instance_id, "/api/v2/monitor/vpn/ipsec?filter=name=@_I2_")
            
            results = fex_tunnel_status.get('results', [])
            if not results:
                self.logger.error("No VPN tunnel results returned.")
                return 0
        
            up_count = 0
            for tunnel in results:
                # Skip tunnels that have a 'parent' key
                if 'parent' in tunnel:
                    continue
        
                proxyids = tunnel.get('proxyid', [])
                for pid in proxyids:
                    if pid.get('status') == 'up':
                        up_count += 1
        
            return up_count
        
        except Exception as e:
            self.logger.exception("Check_FEX_Tunnel_Status Error: " + str(e))
            return None
        

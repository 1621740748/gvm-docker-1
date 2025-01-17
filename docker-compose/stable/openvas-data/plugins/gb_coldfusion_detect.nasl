# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100773");
  script_version("2021-03-24T09:05:19+0000");
  script_tag(name:"last_modification", value:"2021-03-24 09:05:19 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adobe ColdFusion Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Adobe ColdFusion.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

base = "/CFIDE";
file = "/administrator/index.cfm";

url = base + file;

res = http_get_cache( port:port, item:url );

if( "<title>ColdFusion Administrator Login</title>" >< res || "ColdFusion" >< res ) {
  url = base + "/adminapi/administrator.cfc?method=getBuildNumber";
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:TRUE );

  # 2021,0,0,323925
  version = eregmatch( pattern:"([0-9]+,[0-9]+,[0-9]+,[0-9]+)", string:buf );
  if( ! isnull( version[1] ) ) {
    cf_version = str_replace( string:version[1], find:",", replace:"." );
    concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  if( ! cf_version ) {
    url = base + "/services/pdf.cfc?wsdl";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # 10.0.10.284825
      version = eregmatch( pattern:"WSDL created by ColdFusion version ([0-9,]+)-->", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = str_replace( string:version[1], find:",", replace:"." );
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  if( ! cf_version ) {
    url = base + "/adminapi/base.cfc?wsdl";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # (8|9).0.0.251028
      version = eregmatch( pattern:"WSDL created by ColdFusion version ([0-9,]+)-->", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = str_replace( string:version[1], find:",", replace:"." );
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  if( ! cf_version ) {
    url = base + "/administrator/settings/version.cfm";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # (6|7).1.0.hf53797_61
      version = eregmatch( pattern:"Version: ([0-9,hf_]+)</strong>", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = str_replace( string:version[1], find:",", replace:"." );
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      } else {
        # ColdFusion &#x28;2021 Release
        version = eregmatch( pattern:"ColdFusion[^;]+;([0-9]+) Release", string:buf );
        if( ! isnull( version[1] ) ) {
          cf_version = str_replace( string:version[1], find:",", replace:"." );
          concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }
  }

  if( ! cf_version ) {
    url = base + "/administrator/help/index.html";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # Configuring and Administering ColdFusion 11
      version = eregmatch( pattern:"Configuring and Administering ColdFusion ([0-9]+)", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = version[1];
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  if( ! cf_version ) {
    cf_version = "unknown";
    cpe = "cpe:/a:adobe:coldfusion";
  } else {
    cpe = "cpe:/a:adobe:coldfusion:" + cf_version;
  }

  register_product( cpe:cpe, location:url, port:port, service:"www" );
  set_kb_item( name:"adobe/coldfusion/detected", value:TRUE );
  set_kb_item( name:"adobe/coldfusion/http/detected", value:TRUE );

  log_message( data:build_detection_report( app:"Adobe ColdFusion", version:cf_version, install:"/",
                                            cpe:cpe, concluded:version[0], concludedUrl:concUrl ),
               port:port );

  exit( 0 );
}

exit( 0 );

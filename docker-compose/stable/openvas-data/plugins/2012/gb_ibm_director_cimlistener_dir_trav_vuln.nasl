###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Director CIM Server CIMListener Directory Traversal Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802684");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2009-0880");
  script_bugtraq_id(34065);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-12-11 20:37:46 +0530 (Tue, 11 Dec 2012)");
  script_name("IBM Director CIM Server CIMListener Directory Traversal Vulnerability (Windows)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6988);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to traverse the file
  system and specify any library on the system.");

  script_tag(name:"affected", value:"IBM Director version 5.20.3 Service Update 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in IBM Director CIM Server, which allow remote
  attackers to load and execute arbitrary local DLL code via a .. (dot dot)
  in a /CIMListener/ URI in an M-POST request.");

  script_tag(name:"solution", value:"Upgrade to IBM Director version 5.20.3 Service Update 2 or later.");

  script_tag(name:"summary", value:"The host is running IBM Director CIM Server and is prone to
  directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34212");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23074/");
  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20090305-2_IBM_director_privilege_escalation.txt");
  script_xref(name:"URL", value:"https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dmp&S_PKG=director_x_520&S_TACT=sms&lang=en_US&cp=UTF-8");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:6988);

xmlscript = string(
'<?xml version="1.0" encoding="utf-8" ?>' +
'<CIM CIMVERSION="2.0" DTDVERSION="2.0">' +
' <MESSAGE ID="1007" PROTOCOLVERSION="1.0">' +
'  <SIMPLEEXPREQ>' +
'    <EXPMETHODCALL NAME="ExportIndication">' +
'     <EXPPARAMVALUE NAME="NewIndication">' +
'      <INSTANCE CLASSNAME="CIM_AlertIndication" >' +
'        <PROPERTY NAME="Description" TYPE="string">' +
'          <VALUE>Sample CIM_AlertIndication indication</VALUE>' +
'        </PROPERTY>' +
'      </INSTANCE>' +
'    </EXPPARAMVALUE>' +
'  </EXPMETHODCALL>' +
' </SIMPLEEXPREQ>' +
' </MESSAGE>' +
'</CIM>');

url = "/CIMListener/\\..\\..\\..\\..\\..\\mydll";

host = http_host_name(port:port);

req = string("M-POST ", url, " HTTP/1.1\r\n" ,
             "Host: ", host, "\r\n" ,
             "Content-Type: application/xml; charset=utf-8\r\n" ,
             "Content-Length: ", strlen(xmlscript), "\r\n" ,
             "Man: http://www.dmtf.org/cim/mapping/http/v1.0 ; ns=40\r\n" ,
             "CIMOperation: MethodCall\r\n" ,
             "CIMExport: MethodRequest\r\n" ,
             "CIMExportMethod: ExportIndication\r\n",
             "\r\n", xmlscript, "\r\n");
res = http_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200" && "CIMExport: " >< res &&
   "Cannot load module " >< res && "Unknown exception" >< res &&
   "Cannot initialize consumer due to security restrictions" >!< res &&
   "Cannot load outside cimom/bin" >!< res && "CIM CIMVERSION=" >< res)
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

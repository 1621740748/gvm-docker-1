# OpenVAS Vulnerability Test
# Description: RDS / MDAC Vulnerability (msadcs.dll) located
#
# Authors:
# RWT roelof@sensepost.com
#
# Copyright:
# Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10357");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(529);
  script_xref(name:"IAVA", value:"1999-a-0010");
  script_xref(name:"IAVA", value:"1999-t-0003");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-1011");
  script_name("RDS / MDAC Vulnerability (msadcs.dll) located");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The web server is probably susceptible to a common IIS vulnerability discovered by
  'Rain Forest Puppy'.");

  script_tag(name:"impact", value:"This vulnerability enables an attacker to execute arbitrary
  commands on the server with Administrator Privileges.");

  script_tag(name:"solution", value:"See Microsoft security bulletin (MS99-025) for patch information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
sig = http_get_remote_headers(port:port);
if(!sig || "IIS" >!< sig )
  exit(0);

cgi = "/msadc/msadcs.dll";
res = http_is_cgi_installed_ka(item:cgi, port:port);
if(res) {
  report = http_report_vuln_url(port:port, url:cgi);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

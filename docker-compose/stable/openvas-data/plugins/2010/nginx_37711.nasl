###############################################################################
# OpenVAS Vulnerability Test
#
# nginx Terminal Escape Sequence in Logs Command Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100441");
  script_version("2021-02-01T11:36:44+0000");
  script_tag(name:"last_modification", value:"2021-02-01 11:36:44 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)");
  script_bugtraq_id(37711);
  script_cve_id("CVE-2009-4487");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("nginx Terminal Escape Sequence in Logs Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508830");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"nginx is prone to a command-injection vulnerability
  because it fails to adequately sanitize user-supplied input in log files.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands in a terminal.");

  script_tag(name:"affected", value:"This issue affects nginx 0.7.64, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version: version, test_version:"0.7.64" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2011 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:wibu:codemeter_webadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801989");
  script_version("2020-03-04T06:31:22+0000");
  script_cve_id("CVE-2011-3689");
  script_bugtraq_id(48082);
  script_tag(name:"last_modification", value:"2020-03-04 06:31:22 +0000 (Wed, 04 Mar 2020)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CodeMeter WebAdmin 'Licenses.html' Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_codemeter_webadmin_detect.nasl");
  script_mandatory_keys("wibu/codemeter_webadmin/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44800/");
  script_xref(name:"URL", value:"http://forums.cnet.com/7726-6132_102-5144590.html");
  script_xref(name:"URL", value:"http://www.solutionary.com/index/SERT/Vuln-Disclosures/CodeMeter-WebAdmin.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the
  affected site.");

  script_tag(name:"affected", value:"CodeMeter WebAdmin version 4.30 and 3.30.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'BoxSerial' parameter
  to the 'Licenses.html' script is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running CodeMeter WebAdmin and is prone to
  cross-site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:version, test_version:"3.30" ) ||
    version_in_range( version:version, test_version:"4.0", test_version2:"4.30" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

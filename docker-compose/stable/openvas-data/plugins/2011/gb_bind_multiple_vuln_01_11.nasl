###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND 'RRSIG' Record Type Negative Cache Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103030");
  script_version("2021-03-26T13:22:13+0000");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_bugtraq_id(45133, 45137);
  script_cve_id("CVE-2010-3613", "CVE-2010-3614");
  script_name("ISC BIND 'RRSIG' Record Type Negative Cache Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45137");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00938");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00936");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100124923");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"ISC BIND is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A remote denial-of-service vulnerability.

  An attacker can exploit this issue to cause the affected service to
  crash, denying service to legitimate users.

  - A security vulnerability that affects the integrity security property
  of the application.");

  script_tag(name:"affected", value:"ISC BIND versions 9.6.2 to 9.6.2-P2, 9.6-ESV to 9.6-ESV-R2 and 9.7.0 to
  9.7.2-P2 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if( version_in_range( version:version, test_version:"9.6.2", test_version2:"9.6.2p1" ) ||
    version_in_range( version:version, test_version:"9.6", test_version2:"9.6r2" ) ||
    version_in_range( version:version, test_version:"9.7", test_version2:"9.7.2p2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory", install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );

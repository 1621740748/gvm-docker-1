###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Domino iCalendar Meeting Request Parsing Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103067");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_bugtraq_id(46232);

  script_name("IBM Lotus Domino iCalendar Meeting Request Parsing Remote Stack Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46232");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-048");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow remote attackers to
  execute arbitrary code with SYSTEM-level privileges. Successful exploits will completely compromise
  affected computers. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"summary", value:"IBM Lotus Domino is prone to a remote stack-based buffer-overflow
  vulnerability because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"solution", value:"Update to version 8.5 FP1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if (version_is_less( version:version, test_version:"8.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"8.5 FP1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
#
# UCS Director Arbitrary File Overwrite Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:cisco:ucs_director";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105577");
  script_version("2020-09-23T10:02:17+0000");
  script_tag(name:"last_modification", value:"2020-09-23 10:02:17 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 16:14:29 +0100 (Thu, 17 Mar 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");

  script_bugtraq_id(76565);
  script_cve_id("CVE-2015-6259");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_name("UCS Director Arbitrary File Overwrite Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_director_consolidation.nasl");
  script_mandatory_keys("cisco/ucs_director/detected");

  script_tag(name:"summary", value:"Cisco UCS Director is prone to a vulnerability that may allow attackers to over
  write arbitrary files.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input sanitization on specific JSP pages.");

  script_tag(name:"impact", value:"Successful exploits may allow an attacker to overwrite arbitrary system files,
  resulting in system instability or a denial of service condition.");

  script_tag(name:"affected", value:"Cisco UCS Director prior to version 5.2.0.1.");

  script_tag(name:"solution", value:"Update to 5.2.0.1 or newer.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150902-cimcs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"5.2.0.1" ) ) {
  report = report_fixed_ver(  installed_version:version, fixed_version:"5.2.0.1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

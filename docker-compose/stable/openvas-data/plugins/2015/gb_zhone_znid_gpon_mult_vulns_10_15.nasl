###############################################################################
# OpenVAS Vulnerability Test
#
# ZHONE ZNID GPON Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105405");
  script_version("2020-08-05T09:09:42+0000");
  script_tag(name:"last_modification", value:"2020-08-05 09:09:42 +0000 (Wed, 05 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-10-15 14:48:06 +0200 (Thu, 15 Oct 2015)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2014-8356", "CVE-2014-8357", "CVE-2014-9118");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZHONE ZNID GPON < 3.1.241 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_zhone_znid_gpon_consolidation.nasl");
  script_mandatory_keys("dasanzhone/znid/detected");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Insecure object reference (CVE-2014-8356)

  - Admin password disclosure (CVE-2014-8357)

  - Remote code injection (CVE-2014-9118)

  - Stored cross-site scripting

  - Privilege escalation via direct object reference");

  script_tag(name:"solution", value:"Upgrade to version S3.1.241");

  script_tag(name:"summary", value:"ZHONE ZNID GPON is vulnerable to multiple vulnerabilities.");

  script_tag(name:"affected", value:"Model: ZHONE ZNID GPON 2426A (24xx, 24xxA, 42xx, 42xxA, 26xx, and 28xx series models) < S3.0.501");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/536663/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/536666/30/0/threaded");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:dasanzhone:znid_2402_firmware",
                     "cpe:/o:dasanzhone:znid_2403_firmware",
                     "cpe:/o:dasanzhone:znid_2424_firmware",
                     "cpe:/o:dasanzhone:znid_2425_firmware",
                     "cpe:/o:dasanzhone:znid_2426_firmware",
                     "cpe:/o:dasanzhone:znid_2427_firmware",
                     "cpe:/o:dasanzhone:znid_2402a_firmware",
                     "cpe:/o:dasanzhone:znid_2403a_firmware",
                     "cpe:/o:dasanzhone:znid_2424a_firmware",
                     "cpe:/o:dasanzhone:znid_2425a_firmware",
                     "cpe:/o:dasanzhone:znid_2426a_firmware",
                     "cpe:/o:dasanzhone:znid_2427a_firmware",
                     "cpe:/o:dasanzhone:znid_4220_firmware",
                     "cpe:/o:dasanzhone:znid_4221_firmware",
                     "cpe:/o:dasanzhone:znid_4222_firmware",
                     "cpe:/o:dasanzhone:znid_4223_firmware",
                     "cpe:/o:dasanzhone:znid_4224_firmware",
                     "cpe:/o:dasanzhone:znid_4226_firmware",
                     "cpe:/o:dasanzhone:znid_4220a_firmware",
                     "cpe:/o:dasanzhone:znid_4221a_firmware",
                     "cpe:/o:dasanzhone:znid_4222a_firmware",
                     "cpe:/o:dasanzhone:znid_4223a_firmware",
                     "cpe:/o:dasanzhone:znid_4224a_firmware",
                     "cpe:/o:dasanzhone:znid_4226a_firmware",
                     "cpe:/o:dasanzhone:znid_2608t_firmware",
                     "cpe:/o:dasanzhone:znid_2624a_firmware",
                     "cpe:/o:dasanzhone:znid_2624p_firmware",
                     "cpe:/o:dasanzhone:znid_2625a_firmware",
                     "cpe:/o:dasanzhone:znid_2625p_firmware",
                     "cpe:/o:dasanzhone:znid_2628a_firmware",
                     "cpe:/o:dasanzhone:znid_2628p_firmware",
                     "cpe:/o:dasanzhone:znid_2628t_firmware",
                     "cpe:/o:dasanzhone:znid_2644a_firmware",
                     "cpe:/o:dasanzhone:znid_2644p_firmware",
                     "cpe:/o:dasanzhone:znid_2645a_firmware",
                     "cpe:/o:dasanzhone:znid_2645p_firmware",
                     "cpe:/o:dasanzhone:znid_2648a_firmware",
                     "cpe:/o:dasanzhone:znid_2648p_firmware",
                     "cpe:/o:dasanzhone:znid_2648_firmware");

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

if( version_is_less( version:version, test_version:"3.1.241" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1.241" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

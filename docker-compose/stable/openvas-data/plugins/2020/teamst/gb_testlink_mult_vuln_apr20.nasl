# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113670");
  script_version("2020-04-29T02:39:33+0000");
  script_tag(name:"last_modification", value:"2020-04-29 02:39:33 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-07 07:48:50 +0000 (Tue, 07 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2020-8637", "CVE-2020-8638", "CVE-2020-8639", "CVE-2020-12273", "CVE-2020-12274");

  script_name("TestLink <= 1.9.20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("testlink_detect.nasl");
  script_mandatory_keys("testlink/detected");

  script_tag(name:"summary", value:"TestLink is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL injection in dragdroptreenodes.php via the node_id parameter. (CVE-2020-8637)

  - SQL injection in planUrgency.php via the urgency parameter. (CVE-2020-8638)

  - Arbitrary code execution due to unrestricted file uploads in keywordsImport.php. (CVE-2020-8639)

  - A crafted login.php viewer parameter exposes cleartext credentials. (CVE-2020-12273)

  - The lib/cfields/cfieldsExport.php goback_url parameter causes a security risk because it depends on client
    input and is not constrained to lib/cfields/cfieldsView.php at the web site associated with the session. (CVE-2020-12274)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete
  control over the target system.");

  script_tag(name:"affected", value:"TestLink through version 1.9.20.");

  script_tag(name:"solution", value:"The vendor has stated that no new version will be released.
  Instead, users are advised to install the program from source
  from the 'testlink_1_9_20_fixed' branch on the vendor's git repository.");

  script_xref(name:"URL", value:"https://ackcent.com/blog/testlink-1.9.20-unrestricted-file-upload-and-sql-injection/");
  script_xref(name:"URL", value:"http://mantis.testlink.org/view.php?id=8895");
  script_xref(name:"URL", value:"http://mantis.testlink.org/view.php?id=8894");
  script_xref(name:"URL", value:"https://github.com/TestLinkOpenSourceTRMS/testlink-code/tree/testlink_1_9_20_fixed");

  exit(0);
}

CPE = "cpe:/a:testlink:testlink";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.9.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Update from source, see solution details", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

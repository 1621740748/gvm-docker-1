# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113805");
  script_version("2021-03-19T11:30:24+0000");
  script_tag(name:"last_modification", value:"2021-03-19 11:30:24 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-19 11:02:06 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-35581", "CVE-2020-35582", "CVE-2021-24126");

  script_name("WordPress Envira Photo Gallery Plugin < 1.8.3.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/envira-gallery-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin Envira Photo Gallery is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-35581: There is a cross-site scripting (XSS) vulnerability that is exploitable
    via the meta[title] parameter in a POST request to /wp-admin/admin-ajax.php.

  - CVE-2020-35582: There is a cross-site scripting (XSS) vulnerability that is exploitable
    via the post_title parameter in a POST request to /wp-admin/post.php.

  - CVE-2021-24126: An attacker could achieve privilege escalation because the metadata of images
    is not properly sanitised before it is entered in a generated gallery.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site or gain privileged access.");

  script_tag(name:"affected", value:"WordPress Envira Photo Gallery plugin through version 1.8.3.2.");

  script_tag(name:"solution", value:"Update to version 1.8.3.3 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/160924/Envira-Gallery-Lite-1.8.3.2-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f3952bd1-ac2f-4007-9e19-6c44a22465f3");

  exit(0);
}

CPE = "cpe:/a:enviragallery:photo_gallery";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.3.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

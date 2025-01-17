# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813910");
  script_version("2021-05-27T06:00:15+0200");
  script_cve_id("CVE-2018-14028", "CVE-2018-1000773");
  script_bugtraq_id(105306);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-10 13:06:00 +0000 (Wed, 10 Oct 2018)");
  script_tag(name:"creation_date", value:"2018-08-13 12:43:12 +0530 (Mon, 13 Aug 2018)");

  script_name("WordPress <= 4.9.8 Multiple Vulnerabilities - Windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-14028: Plugins uploaded via the admin area are not verified as being
  ZIP files.

  - CVE-2018-1000773: An input validation vulnerability in thumbnail processing that can
  result in remote code execution due to an incomplete fix for CVE-2017-1000600.");

  script_tag(name:"impact", value:"- CVE-2018-14028: Successful exploitation will allow
  remote attackers to upload php files in a predictable wp-content/uploads location and
  execute them.

  - CVE-2018-1000773: An attacker may leverage this issue to upload arbitrary files to the
  affected computer. This can result in arbitrary code execution within the context of the
  vulnerable application.");

  script_tag(name:"affected", value:"All WordPress versions through 4.9.8.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://rastating.github.io/unrestricted-file-upload-via-plugin-uploader-in-wordpress");
  script_xref(name:"URL", value:"https://core.trac.wordpress.org/ticket/44710");
  script_xref(name:"URL", value:"https://github.com/rastating/wordpress-exploit-framework/pull/52");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105306");
  script_xref(name:"URL", value:"https://www.theregister.co.uk/2018/08/20/php_unserialisation_wordpress_vuln/");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"4.9.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Multiple Vulnerabilities-April 2018 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813086");
  script_version("2021-05-27T06:00:15+0200");
  script_cve_id("CVE-2018-10100", "CVE-2018-10101", "CVE-2018-10102");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 13:49:00 +0000 (Fri, 18 May 2018)");
  script_tag(name:"creation_date", value:"2018-04-17 12:10:45 +0530 (Tue, 17 Apr 2018)");
  script_name("WordPress Multiple Vulnerabilities-April 2018 (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The version string was not escaped in the 'get_the_generator' function.

  - The URL validator assumed URLs with the hostname localhost were on the same
    host as the WordPress server.

  - The redirection URL for the login page was not validated or sanitized if
    forced to use HTTPS.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross site scripting, url redirection attacks and
  bypass security restrictions.");

  script_tag(name:"affected", value:"WordPress versions prior to 4.9.5 on Linux");

  script_tag(name:"solution", value:"Update to WordPress version 4.9.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wordPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:wordPort, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"4.9.5"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.9.5", install_path:path);
  security_message(data:report, port:wordPort);
  exit(0);
}
exit(0);

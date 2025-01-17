###############################################################################
# OpenVAS Vulnerability Test
#
# Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-002) (Linux, Version Check)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812584");
  script_version("2021-05-27T09:28:58+0000");
  script_cve_id("CVE-2018-7600");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 18:04:00 +0000 (Fri, 01 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-03-29 10:53:12 +0530 (Thu, 29 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-002) (Linux, Version Check)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to critical remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within multiple subsystems
  of Drupal. This potentially allows attackers to exploit multiple attack
  vectors on a Drupal site, which could result in the site being completely
  compromised.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and completely compromise the site.");

  script_tag(name:"affected", value:"Drupal core versions 6.x and earlier,

  Drupal core versions 8.2.x and earlier,

  Drupal core versions 8.3.x to before 8.3.9,

  Drupal core versions 8.4.x to before 8.4.6,

  Drupal core versions 8.5.x to before 8.5.1 and

  Drupal core versions 7.x to before 7.58 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 8.3.9 or
  8.4.6 or 8.5.1 or 7.58 or later. Please see the referenced links for available updates.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.drupal.org/psa-2018-001");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-002");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.58");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.3.9");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.4.6");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/8.5.1");
  script_xref(name:"URL", value:"https://research.checkpoint.com/uncovering-drupalgeddon-2/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!drupalPort = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:drupalPort, version_regex:"^([0-9.]+)", exit_no_version:TRUE)) {
  exit(0);
}

drupalVer = infos['version'];
path = infos['location'];

if(drupalVer =~ "^(6\.)") {
  fix = "Drupal 6 is End of Life.please contact a D6LTS vendor";
}

if(drupalVer =~ "^(8\.2)" || drupalVer == "8.5.0") {
  fix = "Upgrade to 8.5.1";
}

if(version_in_range(version:drupalVer, test_version:"8.3.0", test_version2:"8.3.8")) {
  fix = "Upgrade to 8.3.9";
}

if(version_in_range(version:drupalVer, test_version:"8.4.0", test_version2:"8.4.5")) {
  fix = "Upgrade to 8.4.6";
}

if(version_in_range(version:drupalVer, test_version:"7.0", test_version2:"7.57")) {
  fix = "Upgrade to 7.58";
}

if(fix) {
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:drupalPort);
  exit(0);
}

exit(99);

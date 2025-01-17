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

CPE = "cpe:/a:paessler:prtg_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146113");
  script_version("2021-06-24T07:50:05+0000");
  script_tag(name:"last_modification", value:"2021-06-24 07:50:05 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-11 06:18:41 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-34547");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("PRTG Network Monitor <= 21.2.68.1492 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to a cross-site request forgery
  (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PRTG Network Monitor allows /editsettings CSRF for user
  account creation.");

  script_tag(name:"affected", value:"PRTG Network Monitor version 21.2.68.1492 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 11th June, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/likhihcv/PRTG_Network_Monitor_20.1.55.1775_CSRF");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "21.2.68.1492")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

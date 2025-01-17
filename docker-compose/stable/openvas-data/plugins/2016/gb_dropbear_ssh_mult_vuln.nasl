# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106381");
  script_version("2021-03-01T15:07:09+0000");
  script_tag(name:"last_modification", value:"2021-03-01 15:07:09 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-11-10 14:18:45 +0700 (Thu, 10 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-7406", "CVE-2016-7407", "CVE-2016-7408", "CVE-2016-7409");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dropbear SSH < 2016.74 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear SSH is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dropbear SSH is prone to multiple vulnerabilities:

  - Message printout was vulnerable to format string injection. A dbclient user who can
  control username or host arguments could potentially run arbitrary code as the dbclient
  user. (CVE-2016-7406)

  - dropbearconvert import of OpenSSH keys could run arbitrary code as the local
  dropbearconvert user when parsing malicious key files. (CVE-2016-7407)

  - dbclient could run arbitrary code as the local dbclient user if particular -m or -c
  arguments are provided. (CVE-2016-7408)

  - bclient or dropbear server could expose process memory to the running user if compiled
  with DEBUG_TRACE and running with -v. (CVE-2016-7409)");

  script_tag(name:"impact", value:"An authenticated attacker may run arbitrary code.");

  script_tag(name:"affected", value:"Dropbear SSH 2016.73 and prior.");

  script_tag(name:"solution", value:"Update to 2016.74 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/14/7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE))) exit(0);
if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "2016.74")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2016.74", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

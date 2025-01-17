# Copyright (C) 2020 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144162");
  script_version("2021-07-22T11:01:40+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-06-24 07:19:30 +0000 (Wed, 24 Jun 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-22 00:15:00 +0000 (Wed, 22 Jul 2020)");

  script_cve_id("CVE-2020-11896", "CVE-2020-11898", "CVE-2020-11899", "CVE-2020-11900", "CVE-2020-11901",
                "CVE-2020-11904", "CVE-2020-11905", "CVE-2020-11906", "CVE-2020-11907", "CVE-2020-11909",
                "CVE-2020-11910", "CVE-2020-11911", "CVE-2020-11912", "CVE-2020-11914");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers Multiple Vulnerabilities - Ripple20 (HPSBPI03666)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Multiple HP printers are vulnerable to multiple vulnerabilities in the Treck
  IP stack (Ripple20).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple potential vulnerabilities may exist in the Treck Inc. networking
  stack used in certain HP and Samsung-branded printers. These may include, but not be limited to, denial of
  service or remote code execution.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c06640149");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/257161");
  script_xref(name:"URL", value:"https://treck.com/vulnerability-response-information/");
  script_xref(name:"URL", value:"https://www.jsof-tech.com/ripple20/");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/h:hp:color_laser_mfp_179fnw",
                     "cpe:/h:hp:color_laser_mfp_178nw",
                     "cpe:/h:hp:laser_mfp_137fnw",
                     "cpe:/h:hp:smart_tank_wireless_450_series",
                     "cpe:/h:hp:ink_tank_wireless_410_series",
                     "cpe:/h:hp:deskjet_3700_all-in-one_printer_series",
                     "cpe:/h:hp:officejet_6950_all-in-one",
                     "cpe:/h:hp:officejet_3830_all-in-one_printer_series",
                     "cpe:/h:hp:deskjet_ink_advantage_3830_all-in-one_printer_series",
                     "cpe:/h:hp:deskjet_3630_all-in-one_printer_series",
                     "cpe:/h:hp:deskjet_ink_advantage_ultra_4720_all-in-one_printer_series",
                     "cpe:/h:hp:deskjet_2700_all-in-one_printer_series",
                     "cpe:/h:hp:deskjet_plus_4100_all-in-one_printer_series",
                     "cpe:/h:hp:deskjet_2600_all-in-one_printer_series",
                     "cpe:/h:hp:officejet_250_mobile_all-in-one",
                     "cpe:/h:hp:officejet_pro_6968_all-in-one");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "cpe:/h:hp:color_laser_mfp_17[89]") {
  if (revcomp(a: version, b: "V3.82.01.08") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V3.82.01.08");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:laser_mfp_137fnw") {
  if (revcomp(a: version, b: "V3.82.01.11") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V3.82.01.11");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:smart_tank_wireless_450_series") {
  if (revcomp(a: version, b: "KDP1FN2020A") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "KDP1FN2020A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:smart_tank_wireless_450_series") {
  if (revcomp(a: version, b: "KEP1FN2020A") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "KEP1FN2020A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_3700_all-in-one_printer_series") {
  if (revcomp(a: version, b: "LYP1FN2020B") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LYP1FN2020B");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:officejet_6950_all-in-one") {
  if (revcomp(a: version, b: "MJM2CN2020B") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MJM2CN2020B");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:officejet_3830_all-in-one_printer_series") {
  if (revcomp(a: version, b: "SPP5FN2021A") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "SPP5FN2021A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_ink_advantage_3830_all-in-one_printer_series") {
  if (revcomp(a: version, b: "SUP1FN2021AR") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "SUP1FN2021A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_3630_all-in-one_printer_series") {
  if (revcomp(a: version, b: "SWP1FN2021C") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "SWP1FN2021C");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_ink_advantage_ultra_4720_all-in-one_printer_series") {
  if (revcomp(a: version, b: "SAP1FN2020B") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "SAP1FN2020BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_2700_all-in-one_printer_series") {
  if (revcomp(a: version, b: "TCP1FN2021D") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TCP1FN2021D");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_plus_4100_all-in-one_printer_series") {
  if (revcomp(a: version, b: "OP1FN2021D") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "OP1FN2021D");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:deskjet_2600_all-in-one_printer_series") {
  if (revcomp(a: version, b: "TJP1FN2020B") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TJP1FN2020B");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:officejet_250_mobile_all-in-one") {
  if (revcomp(a: version, b: "TZM1CN2020B") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TZM1CN2020B");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/h:hp:officejet_pro_6968_all-in-one") {
  if (revcomp(a: version, b: "MCP2CN2020C") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MCP2CN2020C");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);

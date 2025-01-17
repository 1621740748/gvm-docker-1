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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143936");
  script_version("2020-08-11T11:12:56+0000");
  script_tag(name:"last_modification", value:"2020-08-11 11:12:56 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-05-19 09:43:40 +0000 (Tue, 19 May 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-8795");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Integer Overflow Vulnerability in Some Huawei Devices (huawei-sa-20161123-01-vrp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei devices have an integer overflow vulnerability.");

  script_tag(name:"insight", value:"Some Huawei devices have an integer overflow vulnerability. Due to the lack of validation in some field of the packet, a remote, unauthenticated attacker may craft specific IPFPM packets, probably causing the device to reset. (Vulnerability ID: HWPSIRT-2016-04030)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-8795.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause the device to reset.");

  script_tag(name:"affected", value:"Secospace USG6600 versions V500R001C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161123-01-vrp-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware",
                     "cpe:/o:huawei:usg6600_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:cloudengine_(12800|5800|6800|7800)_firmware") {
  if (version =~ "^V100R002C00" || version =~ "^V100R003C00" || version =~ "^V100R003C10" || version =~ "^V100R005C00" ||
      version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware") {
  if (version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version =~ "^V500R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V500R001C30SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.146039");
  script_version("2021-06-10T07:24:50+0000");
  script_tag(name:"last_modification", value:"2021-06-10 07:24:50 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-31 03:20:03 +0000 (Mon, 31 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2021-22411");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Out-of-Bounds Write Vulnerability in Some Huawei Products (huawei-sa-20210506-02-outofbounds)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an out-of-bounds write vulnerability in some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The code of a module has a bad judgment logic. Attackers can
  exploit this vulnerability by performing multiple abnormal activities to trigger the bad logic
  and cause out-of-bounds write. This may compromise the normal service of the module.");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability by performing multiple
  abnormal activities to trigger the bad logic and cause out-of-bounds write. This may compromise
  the normal service of the module.");

  script_tag(name:"affected", value:"NGFW Module versions V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6300 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500 V500R005C00SPC100
  V500R005C00SPC200

  Secospace USG6500 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500 V500R005C00SPC100
  V500R005C00SPC200

  Secospace USG6600 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500 V500R005C00SPC100
  V500R005C00SPC200

  USG9500 versions V500R001C60SPC500 V500R005C00SPC100 V500R005C00SPC200");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210506-02-outofbounds-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:usg6[356]") {
  if (version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600" || version =~ "^V500R001C60SPC500" ||
      version =~ "^V500R005C00SPC100" || version =~ "^V500R005C00SPC200") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C20SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg9500_firmware") {
  if (version =~ "^V500R001C60SPC500" || version =~ "^V500R005C00SPC100" || version =~ "^V500R005C00SPC200") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C20SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.150307");
  script_version("2020-10-15T14:31:37+0000");
  script_tag(name:"last_modification", value:"2020-10-15 14:31:37 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-15 13:58:10 +0200 (Thu, 15 Oct 2020)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Denial of Service Vulnerability in Some Huawei Products (huawei-sa-20200527-01-dos)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a denial of service vulnerability in some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a denial of service vulnerability in some Huawei
  products. Due to improper memory management, memory leakage may occur in some special cases.
  Attackers can perform a series of operations to exploit this vulnerability. Successful exploit may
  cause a denial of service. Huawei has released software updates to fix this vulnerability. This
  advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause a denial of service.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V200R019C00SPC800

  CloudEngine 16800 versions V200R005C20SPC800

  CloudEngine 5800 versions V200R019C00SPC800

  CloudEngine 6800 versions V200R005C20SPC800 V200R019C00SPC800

  CloudEngine 7800 versions V200R019C00SPC800

  CloudEngine 8800 versions V200R019C00SPC800");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200527-01-dos");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_16800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware")  {
  if(version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C10SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C10SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_16800_firmware")  {
  if(version =~ "^V200R005C20SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C10SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C10SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware")  {
  if(version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C10SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C10SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware")  {
  if(version =~ "^V200R005C20SPC800" || version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C10SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C10SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware")  {
  if(version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C10SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C10SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware")  {
  if(version =~ "^V200R019C00SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C10SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C10SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

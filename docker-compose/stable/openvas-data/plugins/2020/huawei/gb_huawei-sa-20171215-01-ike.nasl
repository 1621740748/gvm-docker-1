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
  script_oid("1.3.6.1.4.1.25623.1.0.143988");
  script_version("2020-08-11T11:12:56+0000");
  script_tag(name:"last_modification", value:"2020-08-11 11:12:56 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 06:49:32 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17299");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Insufficient Input Validation Vulnerability in Some Huawei Products (huawei-sa-20171215-01-ike)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an insufficient input validation vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"There is an insufficient input validation vulnerability in some Huawei products. An unauthenticated, remote attacker may send crafted IKE V2 messages to the affected products. Due to the insufficient validation of the messages, successful exploit will cause invalid memory access and result in a denial of service on the affected products. (Vulnerability ID: HWPSIRT-2017-02002)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17299.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit will cause invalid memory access and result in a denial of service on the affected products.");

  script_tag(name:"affected", value:"AR120-S versions V200R006C10SPC300 V200R007C00SPC900

AR1200 versions V200R006C10SPC300 V200R006C13 V200R007C00SPC900 V200R007C02

AR1200-S versions V200R006C10SPC300 V200R007C00SPC900 V200R008C20SPC800PWE

AR150 versions V200R006C10SPC300 V200R007C00SPC900 V200R007C02

AR150-S versions V200R006C10SPC300 V200R007C00SPC900

AR160 versions V200R006C10SPC300 V200R006C12 V200R007C00SPC900 V200R007C02

AR200 versions V200R006C10SPC300 V200R007C00SPC900

AR200-S versions V200R006C10SPC300 V200R007C00SPC900

AR2200 versions V200R006C10SPC300 V200R006C13 V200R006C16PWE V200R007C00SPC900 V200R007C02

AR2200-S versions V200R006C10SPC300 V200R007C00SPC900 V200R008C20SPC800PWE

AR3200 versions V200R006C10SPC200 V200R006C11 V200R007C00 V200R007C02

AR3600 versions V200R006C10SPC300 V200R007C00SPC900

AR510 versions V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00SPC900

DBS3900 TDD LTE versions V100R003C00 V100R004C10

IPS Module versions V500R001C30SPC100PWE

NGFW Module versions V500R002C00SPC100PWE

NIP6300 versions V500R001C30SPC100PWE

NIP6600 versions V500R001C30SPC100PWE

NetEngine16EX versions V200R006C10SPC300 V200R007C00SPC900

SRG1300 versions V200R006C10SPC300 V200R007C00SPC900 V200R007C02

SRG2300 versions V200R006C10SPC300 V200R007C00SPC900 V200R007C02

SRG3300 versions V200R006C10SPC300 V200R007C00SPC900

Secospace USG6300 versions V500R001C30SPC100PWE

Secospace USG6500 versions V500R001C30SPC200PWE

Secospace USG6600 versions V500R001C30SPC100PWE

USG9500 versions V500R001C30SPC100PWE");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171215-01-ike-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar120-s_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar150-s_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar200-s_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:ar510_firmware",
                     "cpe:/o:huawei:dbs3900_tdd_lte_firmware",
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:netengine16ex_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R006C13" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900" || version =~ "^V200R008C20SPC800PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R006C12" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R006C13" || version =~ "^V200R006C16PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900" || version =~ "^V200R008C20SPC800PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R006C10SPC200" || version =~ "^V200R006C11" || version =~ "^V200R007C00" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar510_firmware")  {
  if(version =~ "^V200R006C12" || version =~ "^V200R006C13" || version =~ "^V200R006C15" || version =~ "^V200R006C16" || version =~ "^V200R006C17" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:dbs3900_tdd_lte_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R004C10") {
    if (!patch || version_is_less(version: patch, test_version: "V100R004C10SPC400")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R004C10SPC400");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version =~ "^V500R001C30SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version =~ "^V500R002C00SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version =~ "^V500R001C30SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version =~ "^V500R001C30SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:netengine16ex_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C02") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version =~ "^V500R001C30SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version =~ "^V500R001C30SPC200PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V500R001C30SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9500_firmware")  {
  if(version =~ "^V500R001C30SPC100PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Security Updates May18 (MACOSX)
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813375");
  script_version("2021-05-26T06:00:13+0200");
  script_cve_id("CVE-2018-11362", "CVE-2018-11360", "CVE-2018-11359", "CVE-2018-11358",
                "CVE-2018-11357", "CVE-2018-11356");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2018-05-23 12:18:34 +0530 (Wed, 23 May 2018)");
  script_name("Wireshark Security Updates May18 (MACOSX)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer over-read error in 'epan/dissectors/packet-ldss.c' script.

  - Excessive memory consumption in LTP dissector and other dissectors.

  - A NULL pointer dereference error in 'epan/dissectors/packet-dns.c' script.

  - An off-by-one error in 'epan/dissectors/packet-gsm_a_dtap.c' script.

  - A use-after-free error in 'epan/dissectors/packet-q931.c' script.

  - A NULL pointer dereference error in 'epan/proto.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to make Wireshark crash by injecting a malformed packet onto the wire or by
  convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.6.0, 2.4.0 to 2.4.6,
  and 2.2.0 to 2.2.14 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.6.1 or 2.4.7,
  or 2.2.15 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-25");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-30");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-33");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-31");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-28");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-29");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "2.6.0") {
  fix = "2.6.1";
}

else if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.6")){
  fix = "2.4.7";
}

else if(version_in_range(version:vers, test_version:"2.2.0", test_version2:"2.2.14")){
  fix = "2.2.15";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

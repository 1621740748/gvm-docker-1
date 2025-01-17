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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817705");
  script_version("2021-01-29T09:02:05+0000");
  script_cve_id("CVE-2021-2074", "CVE-2021-2129", "CVE-2021-2128", "CVE-2021-2086",
                "CVE-2021-2111", "CVE-2021-2112", "CVE-2021-2121", "CVE-2021-2124",
                "CVE-2021-2119", "CVE-2021-2120", "CVE-2021-2126", "CVE-2021-2131",
                "CVE-2021-2125", "CVE-2021-2073", "CVE-2021-2127", "CVE-2021-2130",
                "CVE-2021-2123");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-01-29 09:02:05 +0000 (Fri, 29 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-21 23:45:43 +0530 (Thu, 21 Jan 2021)");
  script_name("Oracle VirtualBox Security Updates(Jan2021) - Mac OS X");

  script_tag(name:"summary", value:"The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions 6.1.x prior to 6.1.18
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version 6.1.18
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2021.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^6\.1\." && version_is_less(version:version, test_version:"6.1.18"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"6.1.18", install_path:path);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);

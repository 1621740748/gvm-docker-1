# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815502");
  script_version("2020-06-04T09:02:37+0000");
  script_cve_id("CVE-2019-1134", "CVE-2019-1006");
  script_bugtraq_id(109028, 108978);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-06-04 09:02:37 +0000 (Thu, 04 Jun 2020)");
  script_tag(name:"creation_date", value:"2019-07-10 13:07:37 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft SharePoint Enterprise Server 2013 Multiple Vulnerabilities(KB4475522)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4475522");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws due to,

  - An authentication bypass vulnerability exists in Windows Communication
    Foundation (WCF) and Windows Identity Foundation (WIF), allowing signing
    of SAML tokens with arbitrary symmetric keys.

  - A cross-site-scripting (XSS) vulnerability exists when Microsoft SharePoint
   Server does not properly sanitize a specially crafted web request to an affected
   SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform cross-site scripting attacks on affected systems and run script in
  the security context of the current user and read content that the attacker is
  not authorized to read, use the victim's identity to take actions on the
  SharePoint site on behalf of the user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Enterprise Server 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4475522");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_server', exit_no_version:TRUE )) exit(0);
shareVer = infos['version'];

if(shareVer =~ "^15\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.OSERVER",
                         item:"InstallLocation");
  if(path)
  {
    path = path + "\15.0\bin";

    dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.sharepoint.publishing.dll");
    if(dllVer && version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.5145.0999"))
    {
      report = report_fixed_ver(file_checked:path + "\microsoft.sharepoint.publishing.dll",
               file_version:dllVer, vulnerable_range:"15.0 - 15.0.5145.0999");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);

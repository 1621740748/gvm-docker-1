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
  script_oid("1.3.6.1.4.1.25623.1.0.815151");
  script_version("2020-10-28T08:50:02+0000");
  script_cve_id("CVE-2019-1113", "CVE-2019-1006", "CVE-2019-1083");
  script_bugtraq_id(108977, 108978, 108981);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-28 08:50:02 +0000 (Wed, 28 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-07-10 09:35:44 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (KB4506987)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4506987");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows Communication Foundation (WCF) and Windows Identity Foundation
    (WIF), allowing signing of SAML tokens with arbitrary symmetric keys.

  - An error when Microsoft Common Object Runtime Library improperly handles web
    requests.

  - Because the .NET Framework fails to check the source markup
    of a file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges, conduct denial-of-service condition and execute
  arbitrary code.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.8 on Microsoft Windows 10 Version 1703.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4506987");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(edgeVer =~ "^11\.0\.15063")
{
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")){
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")){
      if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")){
        exit(0);
      }
    }
  }

  key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

  foreach key(key_list)
  {
    if(".NETFramework" >< key)
    {
      foreach item (registry_enum_keys(key:key))
      {
        NetPath = registry_get_sz(key:key + item, item:"InstallRoot");
        if(NetPath && "\Microsoft.NET\Framework" >< NetPath)
        {
          foreach item (registry_enum_keys(key:key))
          {
            dotPath = NetPath + item;
            dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.workflow.runtime.dll");
            if(dllVer)
            {
              ## https://support.microsoft.com/en-us/help/4506987
              if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.3824"))
              {
                vulnerable_range = "4.8 - 4.8.3824" ;
                break;
              }
            }
          }
          if(vulnerable_range){
            break;
          }
        }
      }
    }

    if((!vulnerable_range) && "ASP.NET" >< key)
    {
      foreach item (registry_enum_keys(key:key))
      {
        dotPath = registry_get_sz(key:key + item, item:"Path");
        if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
        {
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.workflow.runtime.dll");
          if(dllVer)
          {
            ## https://support.microsoft.com/en-us/help/4506987
            if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.3824"))
            {
              vulnerable_range = "4.8 - 4.8.3824" ;
              break;
            }
          }
        }
      }
    }

    ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
    if((!vulnerable_range) && "NET Framework Setup" >< key)
    {
      dotPath = registry_get_sz(key:key, item:"InstallPath");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.workflow.runtime.dll");
        if(dllVer)
        {
          ## https://support.microsoft.com/en-us/help/4506987
          if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.3824")){
            vulnerable_range = "4.8 - 4.8.3824" ;
          }
        }
      }
    }

    if(vulnerable_range)
    {
      report = report_fixed_ver(file_checked:dotPath + "System.workflow.runtime.dll",
                                file_version:dllVer, vulnerable_range:vulnerable_range);
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);

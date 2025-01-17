###############################################################################
# OpenVAS Vulnerability Test
#
# Windows IExpress Untrusted Search Path Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813808");
  script_version("2021-06-24T02:00:31+0000");
  script_cve_id("CVE-2018-0598");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-17 17:21:00 +0000 (Fri, 17 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-08-02 11:18:18 +0530 (Thu, 02 Aug 2018)");
  script_name("Windows IExpress Untrusted Search Path Vulnerability");

  script_tag(name:"summary", value:"This host has IExpress bundled with
  Microsoft Windows and is prone to an untrusted search path vulnerability.");

  script_tag(name:"vuldetect", value:"Check for the presence of IExpress
  (IEXPRESS.EXE).");

  script_tag(name:"insight", value:"The flaw exists due to an untrusted
  search path error in self-extracting archive files created by IExpress
  bundled with Microsoft Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code with the privilege of the user invoking a vulnerable
  self-extracting archive file.");

  script_tag(name:"affected", value:"IExpress bundled with Microsoft Windows");

  script_tag(name:"solution", value:"As a workaround save self-extracting archive
  files into a newly created directory, and confirm there are no unrelated files in
  the directory and make sure there are no suspicious files in the directory where
  self-extracting archive files are saved.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN72748502/index.html");
  script_xref(name:"URL", value:"https://blogs.technet.microsoft.com/srd/2018/04/04/triaging-a-dll-planting-vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"iexpress.exe");
if(fileVer)
{
  report = report_fixed_ver(file_checked:sysPath + "\IEXPRESS.EXE",
                            file_version:fileVer, fixed_version:"Workaround");
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Silverlight Remote Code Execution Vulnerability (3126036)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806186");
  script_version("2020-06-08T14:40:48+0000");
  script_cve_id("CVE-2016-0034");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2016-01-13 08:51:19 +0530 (Wed, 13 Jan 2016)");
  script_name("Microsoft Silverlight Remote Code Execution Vulnerability (3126036)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3126036");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-006");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-006.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due when Microsoft
  Silverlight decodes strings using a malicious decoder that can return negative
  offsets that cause Silverlight to replace unsafe object headers with contents
  provided by an attacker.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_in_range(version:msl_ver, test_version:"5.0", test_version2:"5.1.41211.0"))
  {
    report = 'Silverlight version: ' + msl_ver  + '\n' +
             'Vulnerable range:    5.0 - 5.1.41211.0';
    security_message(data:report);
    exit(0);
  }
}

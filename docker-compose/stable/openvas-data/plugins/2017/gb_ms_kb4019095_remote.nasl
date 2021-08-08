###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL Server 2016 Information Disclosure Vulnerability-KB4019095 (Remote)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811292");
  script_version("2021-04-08T12:57:28+0000");
  script_cve_id("CVE-2017-8516");
  script_bugtraq_id(100041);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-08 12:57:28 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-08-09 15:25:00 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft SQL Server 2016 Information Disclosure Vulnerability-KB4019095 (Remote)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4019095");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in Microsoft
  SQL Server Analysis Services when it improperly enforces permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and access to an affected SQL server
  database.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2016 x64 Service Pack 1 (CU).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019095");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("mssqlserver_detect.nasl");
  script_mandatory_keys("MS/SQLSERVER/Running");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:microsoft:sql_server_2016",
                     "cpe:/a:microsoft:sql_server_2016:sp1");

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!vers = get_app_version(cpe:cpe, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"13.0.2000.0", test_version2:"13.0.4445.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"13.0.2000.0 - 13.0.4445.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
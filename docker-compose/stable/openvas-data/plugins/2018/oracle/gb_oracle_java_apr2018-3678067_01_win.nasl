###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Security Updates (apr2018-3678067) 01 - Windows
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
  script_oid("1.3.6.1.4.1.25623.1.0.813098");
  script_version("2021-06-30T02:00:35+0000");
  script_cve_id("CVE-2018-2783");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-04-18 19:05:00 +0530 (Wed, 18 Apr 2018)");
  script_name("Oracle Java SE Security Updates (apr2018-3678067) 01 - Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to a remote security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error
  in the 'Security' component of Java SE.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to affect confidentiality and integrity via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0.181 and
  earlier, 1.7.0.161 and earlier, 1.8.0.152 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]\.") {
  if((version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.181")) ||
     (version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.161")) ||
     (version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.152"))) {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(0);

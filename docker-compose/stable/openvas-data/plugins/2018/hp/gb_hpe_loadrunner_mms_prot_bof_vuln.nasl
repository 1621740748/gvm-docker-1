# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812940");
  script_version("2021-06-15T02:00:29+0000");
  script_cve_id("CVE-2016-8512");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-09 17:39:00 +0000 (Fri, 09 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-02-21 18:29:57 +0530 (Wed, 21 Feb 2018)");
  script_name("HPE LoadRunner MMS Protocol Buffer Overflow RCE Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE LoadRunner
  and is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to buffer overflow
  error in the MMS protocol due to improper validation of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service condition or the execution of arbitrary
  code.");

  script_tag(name:"affected", value:"HPE LoadRunner");

  script_tag(name:"solution", value:"See the referenced vendor advisory for mitigation steps.");

  script_tag(name:"solution_type", value:"Mitigation");
  ##Lowering QOD as Mitigation is available as solution
  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c05354136");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
security_message(data:report);
exit(0);

###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Oct 2013 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804118");
  script_version("2020-10-19T15:33:20+0000");
  script_cve_id("CVE-2013-5831", "CVE-2013-5832", "CVE-2013-5812", "CVE-2013-5824",
                "CVE-2013-5818", "CVE-2013-5819", "CVE-2013-5823", "CVE-2013-5789",
                "CVE-2013-5820", "CVE-2013-5852", "CVE-2013-5848", "CVE-2013-5776",
                "CVE-2013-5772", "CVE-2013-5784", "CVE-2013-5787");
  script_bugtraq_id(63129, 63158, 63126, 63157, 63141, 63110, 63139, 63133, 63130,
                    63124, 63156, 63152, 63089, 63098, 63155);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-10-25 19:03:24 +0530 (Fri, 25 Oct 2013)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Oct 2013 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Oracle Java SE JRE and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exists.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"Oracle Java SE 7 update 40 and earlier, 6 update 60 and earlier on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63158");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

if(vers =~ "^1\.[67]") {
  if(version_in_range(version:vers, test_version:"1.6.0.0", test_version2:"1.6.0.60")||
     version_in_range(version:vers, test_version:"1.7.0.0", test_version2:"1.7.0.40")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

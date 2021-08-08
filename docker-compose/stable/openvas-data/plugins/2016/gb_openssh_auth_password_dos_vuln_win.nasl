###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH Denial of Service And User Enumeration Vulnerabilities (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809121");
  script_version("2019-05-21T12:48:06+0000");
  script_cve_id("CVE-2016-6515", "CVE-2016-6210");
  script_bugtraq_id(92212);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 12:48:06 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2016-08-18 10:29:27 +0530 (Thu, 18 Aug 2016)");
  script_name("OpenSSH Denial of Service And User Enumeration Vulnerabilities (Windows)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_openssh_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.3");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jul/51");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2016-6210");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/08/01/2");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to denial of service and user enumeration vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The auth_password function in 'auth-passwd.c' script does not limit password
    lengths for password authentication.

  - The sshd in OpenSSH, when SHA256 or SHA512 are used for user password hashing
    uses BLOWFISH hashing on a static password when the username does not exist
    and it takes much longer to calculate SHA256/SHA512 hash than BLOWFISH hash.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  remote attackers to cause a denial of service (crypt CPU consumption) and
  to enumerate users by leveraging the timing difference between responses
  when a large password is provided.");

  script_tag(name:"affected", value:"OpenSSH versions before 7.3 on Windows");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.3", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
###############################################################################
# OpenVAS Vulnerability Test
#
# NTP.org 'ntp' 'decodenetnum' And 'loop counter underrun' DoS Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810221");
  script_version("2021-06-24T07:50:05+0000");
  script_cve_id("CVE-2015-7871", "CVE-2015-7855", "CVE-2015-7854", "CVE-2015-7853", "CVE-2015-7852",
                "CVE-2015-7851", "CVE-2015-7850", "CVE-2015-7849", "CVE-2015-7848", "CVE-2015-7701",
                "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7691", "CVE-2015-7692",
                "CVE-2015-7702");
  script_bugtraq_id(77283, 77275);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-24 07:50:05 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2016-11-29 12:32:57 +0530 (Tue, 29 Nov 2016)");
  script_name("NTP.org 'ntpd' 'decodenetnum' And 'loop counter underrun' DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40840");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug2913");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#October_2015_NTP_4_2_8p4_Securit");

  script_tag(name:"summary", value:"The host is running NTP.org's reference
  implementation of NTP server, ntpd and is prone to multiple denial of service
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors are due to:

  - CVE-2015-7871 NAK to the Future: Symmetric association authentication bypass via crypto-NAK

  - CVE-2015-7855 decodenetnum() will ASSERT botch instead of returning FAIL on some bogus values

  - CVE-2015-7854 Password Length Memory Corruption Vulnerability

  - CVE-2015-7853 Invalid length data provided by a custom refclock driver could cause a buffer overflow

  - CVE-2015-7852 ntpq atoascii() Memory Corruption Vulnerability

  - CVE-2015-7851 saveconfig Directory Traversal Vulnerability

  - CVE-2015-7850 remote config logfile-keyfile

  - CVE-2015-7849 trusted key use-after-free

  - CVE-2015-7848 mode 7 loop counter underrun

  - CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC

  - CVE-2015-7703 configuration directives 'pidfile' and 'driftfile' should only be allowed locally

  - CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD should validate the origin timestamp field

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete autokey data packet length checks");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"NTP.org's ntpd versions 4.x prior to 4.2.8p4 and 4.3.0
  prior to 4.3.77.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd 4.2.8p4 or 4.3.77 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if(version =~ "^4\.[0-2]") {
  if(revcomp(a:version, b:"4.2.8p4") < 0) {
    VULN = TRUE;
    fix = "4.2.8p4";
  }
}

else if(version =~ "^4\.3") {
  if(revcomp(a:version, b:"4.3.77") < 0) {
    VULN = TRUE;
    fix = "4.3.77";
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, proto:proto, data:report);
  exit(0);
}

exit(99);

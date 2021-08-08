# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1330");
  script_version("2021-07-13T10:05:59+0000");
  script_cve_id("CVE-2016-9586", "CVE-2017-1000254", "CVE-2017-8817", "CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122", "CVE-2018-1000301");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-13 10:05:59 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-01-23 11:21:53 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2018-1330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1330");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1330");
  script_xref(name:"URL", value:"https://github.com/curl/curl/commit/415d2e7cb7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'curl' package(s) announced via the EulerOS-SA-2018-1330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that libcurl did not safely parse FTP URLs when using the CURLOPT_FTP_FILEMETHOD method. An attacker, able to provide a specially crafted FTP URL to an application using libcurl, could write a NULL byte at an arbitrary location, resulting in a crash, or an unspecified behavior.(CVE-2018-1000120)

A NULL pointer dereference flaw was found in the way libcurl checks values returned by the openldap ldap_get_attribute_ber() function. A malicious LDAP server could use this flaw to crash a libcurl client application via a specially crafted LDAP reply.(CVE-2018-1000121)

A buffer over-read exists in curl 7.20.0 to and including curl 7.58.0 in the RTSP+RTP handling code that allows an attacker to cause a denial of service or information leakage(CVE-2018-1000122)

curl version curl 7.20.0 to and including curl 7.59.0 contains a Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded rtsp content.(CVE-2018-1000301)

curl version curl 7.20.0 to and including curl 7.59.0 contains a Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded rtsp content.(CVE-2016-9586)

libcurl may read outside of a heap allocated buffer when doing FTP. When libcurl connects to an FTP server and successfully logs in (anonymous or not), it asks the server for the current directory with the `PWD` command. The server then responds with a 257 response containing the path, inside double quotes. The returned path name is then kept by libcurl for subsequent uses. Due to a flaw in the string parser for this directory name, a directory name passed like this but without a closing double quote would lead to libcurl not adding a trailing NUL byte to the buffer holding the name. When libcurl would then later access the string, it could read beyond the allocated heap buffer and crash or wrongly access data beyond the buffer, thinking it was part of the path. A malicious server could abuse this fact and effectively prevent libcurl-based clients to work with it - the PWD command is always issued on new FTP connections and the mistake has a high chance of causing a segfault. The simple fact that this has issue remained undiscovered for this long could suggest that malformed PWD responses are rare in benign servers. We are not aware of any exploit of this flaw. This bug was introduced in commit [415d2e7cb7]([link moved to references]), March 2005. In libcurl version 7.56.0, the parser always ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization 2.5.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROSVIRT-2.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~35.h7", rls:"EULEROSVIRT-2.5.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

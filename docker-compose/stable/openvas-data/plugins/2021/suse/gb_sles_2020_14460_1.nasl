# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14460.1");
  script_cve_id("CVE-2019-12519", "CVE-2019-12520", "CVE-2019-12521", "CVE-2019-12523", "CVE-2019-12524", "CVE-2019-12525", "CVE-2019-12526", "CVE-2019-12528", "CVE-2019-12529", "CVE-2019-13345", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679", "CVE-2019-18860", "CVE-2020-11945", "CVE-2020-14059", "CVE-2020-15049", "CVE-2020-8449", "CVE-2020-8450", "CVE-2020-8517");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-11 14:43:00 +0000 (Thu, 11 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14460-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14460-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014460-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the SUSE-SU-2020:14460-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid3 fixes the following issues:

Fixed a Cache Poisoning and Request Smuggling attack (CVE-2020-15049,
 bsc#1173455)

Fixed incorrect buffer handling that can result in cache poisoning,
 remote execution, and denial of service attacks when processing ESI
 responses (CVE-2019-12519, CVE-2019-12521, bsc#1169659)

Fixed handling of hostname in cachemgr.cgi (CVE-2019-18860, bsc#1167373)

Fixed a potential remote execution vulnerability when using HTTP Digest
 Authentication (CVE-2020-11945, bsc#1170313)

Fixed a potential ACL bypass, cache-bypass and cross-site scripting
 attack when processing invalid HTTP Request messages (CVE-2019-12520,
 CVE-2019-12524, bsc#1170423)

Fixed a potential denial of service when processing TLS certificates
 during HTTPS connections (CVE-2020-14059, bsc#1173304)

Fixed a potential denial of service associated with incorrect buffer
 management of HTTP Basic Authentication credentials (bsc#1141329,
 CVE-2019-12529)

Fixed an incorrect buffer management resulting in vulnerability to a
 denial of service during processing of HTTP Digest Authentication
 credentials (bsc#1141332, CVE-2019-12525)

Fix XSS via user_name or auth parameter in cachemgr.cgi (bsc#1140738,
 CVE-2019-13345)

Fixed a potential code execution vulnerability (CVE-2019-12526,
 bsc#1156326)

Fixed HTTP Request Splitting in HTTP message processing and information
 disclosure in HTTP Digest Authentication (CVE-2019-18678,
 CVE-2019-18679, bsc#1156323, bsc#1156324)

Fixed a security issue allowing a remote client ability to cause use a
 buffer overflow when squid is acting as reverse-proxy. (CVE-2020-8449,
 CVE-2020-8450, bsc#1162687)

Fixed a security issue allowing for information disclosure in FTP
 gateway (CVE-2019-12528, bsc#1162689)

Fixed a security issue in ext_lm_group_acl when processing NTLM
 Authentication credentials. (CVE-2020-8517, bsc#1162691)

Fixed Cross-Site Request Forgery in HTTP Request processing
 (CVE-2019-18677, bsc#1156328)

Disable urn parsing and parsing of unknown schemes (bsc#1156329,
 CVE-2019-12523, CVE-2019-18676)");

  script_tag(name:"affected", value:"'squid3' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"squid3", rpm:"squid3~3.1.23~8.16.37.12.1", rls:"SLES11.0SP4"))) {
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

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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852061");
  script_version("2021-06-28T11:00:33+0000");
  script_cve_id("CVE-2018-0732", "CVE-2018-0737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-08 12:15:00 +0000 (Tue, 08 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-10-26 06:40:25 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for openssl-1_0_0 (openSUSE-SU-2018:3015-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:3015-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_0_0'
  package(s) announced via the openSUSE-SU-2018:3015-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_0_0 to 1.0.2p fixes the following issues:

  These security issues were fixed:

  - Prevent One&amp Done side-channel attack on RSA that allowed physically near
  attackers to use EM emanations to recover information (bsc#1104789)

  - CVE-2018-0737: The RSA Key generation algorithm has been shown to be
  vulnerable to a cache timing side channel attack. An attacker with
  sufficient access to mount cache timing attacks during the RSA key
  generation process could have recovered the private key (bsc#1089039)

  - CVE-2018-0732: During key agreement in a TLS handshake using a DH(E)
  based ciphersuite a malicious server could have sent a very large prime
  value to the client. This caused the client to spend an unreasonably
  long period of time generating a key for this prime resulting in a hang
  until the client has finished. This could be exploited in a Denial Of
  Service attack (bsc#1097158)

  - Make problematic ECDSA sign addition length-invariant

  - Add blinding to ECDSA and DSA signatures to protect against side channel
  attacks

  This non-security issue was fixed:

  - Add openssl(cli) Provide so the packages that require the openssl binary
  can require this instead of the new openssl meta package (bsc#1101470)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1110=1");

  script_tag(name:"affected", value:"openssl-1_0_0 on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam", rpm:"libopenssl1_0_0-steam~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-debuginfo", rpm:"libopenssl1_0_0-steam-debuginfo~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-cavs", rpm:"openssl-1_0_0-cavs~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-cavs-debuginfo", rpm:"openssl-1_0_0-cavs-debuginfo~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debuginfo", rpm:"openssl-1_0_0-debuginfo~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debugsource", rpm:"openssl-1_0_0-debugsource~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-doc", rpm:"openssl-1_0_0-doc~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel-32bit", rpm:"libopenssl-1_0_0-devel-32bit~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit-debuginfo", rpm:"libopenssl1_0_0-32bit-debuginfo~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-32bit", rpm:"libopenssl1_0_0-steam-32bit~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-32bit-debuginfo", rpm:"libopenssl1_0_0-steam-32bit-debuginfo~1.0.2p~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
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

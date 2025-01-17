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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1536");
  script_version("2021-03-05T07:09:40+0000");
  script_cve_id("CVE-2019-17006", "CVE-2020-12399", "CVE-2020-12400", "CVE-2020-12401", "CVE-2020-12402", "CVE-2020-12403");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-03-05 07:09:40 +0000 (Fri, 05 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-05 07:09:40 +0000 (Fri, 05 Mar 2021)");
  script_name("Huawei EulerOS: Security Advisory for nss-softokn (EulerOS-SA-2021-1536)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1536");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1536");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'nss-softokn' package(s) announced via the EulerOS-SA-2021-1536 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS. When using multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest threat from this vulnerability is to confidentiality and system availability.(CVE-2020-12403)

When converting coordinates from projective to affine, the modular inversion was not performed in constant time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox  80 and Firefox for Android  80.CVE-2020-12400)

NSS has shown timing differences when performing DSA signatures, which was exploitable and could eventually leak private keys. This vulnerability affects Thunderbird  68.9.0, Firefox  77, and Firefox ESR  68.9.(CVE-2020-12399)

During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes. *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected, but products built on top of it might. This vulnerability affects Firefox  78.(CVE-2020-12402)

During ECDSA signature generation, padding applied in the nonce designed to ensure constant-time scalar multiplication was removed, resulting in variable-time execution dependent on secret data. This vulnerability affects Firefox  80 and Firefox for Android  80.(CVE-2020-12401)

In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length checks. In cases where the application calling the library did not perform a sanity check on the inputs it could result in a crash due to a buffer overflow.(CVE-2019-17006)");

  script_tag(name:"affected", value:"'nss-softokn' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.39.0~2.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.39.0~2.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
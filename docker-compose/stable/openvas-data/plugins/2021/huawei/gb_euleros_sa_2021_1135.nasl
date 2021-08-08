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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1135");
  script_version("2021-02-02T07:44:12+0000");
  script_cve_id("CVE-2020-16592", "CVE-2020-16598", "CVE-2020-35493", "CVE-2020-35494", "CVE-2020-35495", "CVE-2020-35496", "CVE-2020-35507");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-02-02 07:44:12 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-02 07:44:12 +0000 (Tue, 02 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2021-1135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1135");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1135");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'binutils' package(s) announced via the EulerOS-SA-2021-1135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Null Pointer Dereference in debug_get_real_type could result in DoS(CVE-2020-16598)

A use after free issue exists in the Binary File Descriptor (BFD) library (aka libbfd) in GNU Binutils 2.34 in bfd_hash_lookup, as demonstrated in nm-new, that can cause a denial of service via a crafted file.(CVE-2020-16592)

There's a flaw in bfd_pef_parse_function_stubs of bfd/pef.c in binutils which could allow an attacker who is able to submit a crafted file to be processed by objdump to cause a NULL pointer dereference. The greatest threat of this flaw is to application availability. This flaw affects binutils versions prior to 2.34.(CVE-2020-35507)

A flaw exists in binutils in bfd/pef.c. An attacker who is able to submit a crafted PEF file to be parsed by objdump could cause a heap buffer overflow - out-of-bounds read that could lead to an impact to application availability. This flaw affects binutils versions prior to 2.34.(CVE-2020-35493)

There's a flaw in binutils /opcodes/tic4x-dis.c. An attacker who is able to submit a crafted input file to be processed by binutils could cause usage of uninitialized memory. The highest threat is to application availability with a lower threat to data confidentiality. This flaw affects binutils versions prior to 2.34.(CVE-2020-35494)

There's a flaw in binutils /bfd/pef.c. An attacker who is able to submit a crafted input file to be processed by the objdump program could cause a null pointer dereference. The greatest threat from this flaw is to application availability. This flaw affects binutils versions prior to 2.34.(CVE-2020-35495)

There's a flaw in bfd_pef_scan_start_address() of bfd/pef.c in binutils which could allow an attacker who is able to submit a crafted file to be processed by objdump to cause a NULL pointer dereference. The greatest threat of this flaw is to application availability. This flaw affects binutils versions prior to 2.34.(CVE-2020-35496)");

  script_tag(name:"affected", value:"'binutils' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.31.1~13.h21.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.31.1~13.h21.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
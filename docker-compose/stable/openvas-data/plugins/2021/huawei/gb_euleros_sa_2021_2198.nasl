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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2198");
  script_version("2021-07-13T12:59:21+0000");
  script_cve_id("CVE-2020-15389", "CVE-2020-27814", "CVE-2020-27823", "CVE-2020-27824", "CVE-2020-27841", "CVE-2020-27843", "CVE-2020-27845");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-13 12:59:21 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 12:59:21 +0000 (Tue, 13 Jul 2021)");
  script_name("Huawei EulerOS: Security Advisory for openjpeg2 (EulerOS-SA-2021-2198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2198");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2198");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'openjpeg2' package(s) announced via the EulerOS-SA-2021-2198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There's a flaw in src/lib/openjp2/pi.c of openjpeg in versions prior to 2.4.0. If an attacker is able to provide untrusted input to openjpeg's conversion/encoding functionality, they could cause an out-of-bounds read. The highest impact of this flaw is to application availability.(CVE-2020-27845)

A flaw was found in OpenJPEG in versions prior to 2.4.0. This flaw allows an attacker to provide specially crafted input to the conversion or encoding functionality, causing an out-of-bounds read. The highest threat from this vulnerability is system availability.(CVE-2020-27843)

There's a flaw in openjpeg in versions prior to 2.4.0 in src/lib/openjp2/pi.c. When an attacker is able to provide crafted input to be processed by the openjpeg encoder, this could cause an out-of-bounds read. The greatest impact from this flaw is to application availability.(CVE-2020-27841)

A heap-buffer overflow was found in the way openjpeg2 handled certain PNG format files. An attacker could use this flaw to cause an application crash or in some cases execute arbitrary code with the permission of the user running such an application.(CVE-2020-27814)

A flaw was found in OpenJPEGs encoder in the opj_dwt_calc_explicit_stepsizes() function. This flaw allows an attacker who can supply crafted input to decomposition levels to cause a buffer overflow. The highest threat from this vulnerability is to system availability.(CVE-2020-27824)

A flaw was found in OpenJPEGs encoder. This flaw allows an attacker to pass specially crafted x,y offset input to OpenJPEG to use during encoding. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2020-27823)

jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free that can be triggered if there is a mix of valid and invalid files in a directory operated on by the decompressor. Triggering a double-free may also be possible. This is related to calling opj_image_destroy twice.(CVE-2020-15389)");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.1~2.h3.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852535");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-06-04 02:00:54 +0000 (Tue, 04 Jun 2019)");
  script_name("openSUSE: Security Advisory for libvirt (openSUSE-SU-2019:1505-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1505-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the openSUSE-SU-2019:1505-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvirt fixes the following issues:

  Four new speculative execution information leak issues have been
  identified in Intel CPUs. (bsc#1111331)

  - CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)

  - CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)

  - CVE-2018-12130: Microarchitectural Load Port Data Sampling (MLPDS)

  - CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory
  (MDSUM)

  These updates contain the libvirt adjustments, that pass through the new
  'md-clear' CPU flag (bsc#1135273).

  This update was imported from the SUSE:SLE-15:Update update project.
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1505=1");

  script_tag(name:"affected", value:"'libvirt' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin", rpm:"libvirt-admin~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin-debuginfo", rpm:"libvirt-admin-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-debuginfo", rpm:"libvirt-client-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-debuginfo", rpm:"libvirt-daemon-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface-debuginfo", rpm:"libvirt-daemon-driver-interface-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc-debuginfo", rpm:"libvirt-daemon-driver-lxc-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network-debuginfo", rpm:"libvirt-daemon-driver-network-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev-debuginfo", rpm:"libvirt-daemon-driver-nodedev-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter-debuginfo", rpm:"libvirt-daemon-driver-nwfilter-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu-debuginfo", rpm:"libvirt-daemon-driver-qemu-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret-debuginfo", rpm:"libvirt-daemon-driver-secret-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core", rpm:"libvirt-daemon-driver-storage-core~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core-debuginfo", rpm:"libvirt-daemon-driver-storage-core-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk", rpm:"libvirt-daemon-driver-storage-disk~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk-debuginfo", rpm:"libvirt-daemon-driver-storage-disk-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi", rpm:"libvirt-daemon-driver-storage-iscsi~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi-debuginfo", rpm:"libvirt-daemon-driver-storage-iscsi-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical", rpm:"libvirt-daemon-driver-storage-logical~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical-debuginfo", rpm:"libvirt-daemon-driver-storage-logical-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath", rpm:"libvirt-daemon-driver-storage-mpath~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath-debuginfo", rpm:"libvirt-daemon-driver-storage-mpath-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi", rpm:"libvirt-daemon-driver-storage-scsi~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi-debuginfo", rpm:"libvirt-daemon-driver-storage-scsi-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-uml", rpm:"libvirt-daemon-driver-uml~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-uml-debuginfo", rpm:"libvirt-daemon-driver-uml-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-vbox", rpm:"libvirt-daemon-driver-vbox~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-vbox-debuginfo", rpm:"libvirt-daemon-driver-vbox-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-hooks", rpm:"libvirt-daemon-hooks~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-qemu", rpm:"libvirt-daemon-qemu~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-uml", rpm:"libvirt-daemon-uml~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-vbox", rpm:"libvirt-daemon-vbox~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-debugsource", rpm:"libvirt-debugsource~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs", rpm:"libvirt-libs~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs-debuginfo", rpm:"libvirt-libs-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock-debuginfo", rpm:"libvirt-lock-sanlock-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss", rpm:"libvirt-nss~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss-debuginfo", rpm:"libvirt-nss-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-plugin-libvirt", rpm:"wireshark-plugin-libvirt~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-plugin-libvirt-debuginfo", rpm:"wireshark-plugin-libvirt-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-32bit-debuginfo", rpm:"libvirt-client-32bit-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl", rpm:"libvirt-daemon-driver-libxl~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl-debuginfo", rpm:"libvirt-daemon-driver-libxl-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd", rpm:"libvirt-daemon-driver-storage-rbd~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd-debuginfo", rpm:"libvirt-daemon-driver-storage-rbd-debuginfo~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-xen", rpm:"libvirt-daemon-xen~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel-32bit", rpm:"libvirt-devel-32bit~4.0.0~lp150.7.14.1", rls:"openSUSELeap15.0"))) {
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

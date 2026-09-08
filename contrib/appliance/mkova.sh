#!/bin/bash
# mkova.sh — wrap a stream-optimised VMDK in an OVA that VirtualBox and
# VMware will import.
#
# An OVA is a tar (in a specific member order: the .ovf first, then the
# manifest, then the disk) of an OVF descriptor plus the disk. Nothing here
# needs VirtualBox installed, which matters because the CI runner that
# builds the image does not have it.
set -euo pipefail

VMDK=""; NAME=""; OUT=""; MEMORY_MB=4096; CPUS=2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vmdk) VMDK="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --memory) MEMORY_MB="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        *) echo "mkova.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -s "$VMDK" && -n "$NAME" && -n "$OUT" ]] || { echo "mkova.sh: --vmdk, --name and --out are required" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DISK_BYTES="$(stat -c %s "$VMDK")"
# The virtual size the guest sees, which is what the OVF advertises; the
# file itself is smaller because it is stream-optimised.
CAPACITY="$(qemu-img info --output=json "$VMDK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')"

cp "$VMDK" "$WORK/$NAME-disk1.vmdk"

cat > "$WORK/$NAME.ovf" <<OVF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope ovf:version="1.0" xml:lang="en-US"
    xmlns="http://schemas.dmtf.org/ovf/envelope/1"
    xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
    xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
    xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">
  <References>
    <File ovf:href="$NAME-disk1.vmdk" ovf:id="file1" ovf:size="$DISK_BYTES"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="$CAPACITY" ovf:diskId="vmdisk1" ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="NAT">
      <Description>NAT. The appliance needs outbound access to reach the Bitcoin network.</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="$NAME">
    <Info>satd appliance</Info>
    <Name>$NAME</Name>
    <OperatingSystemSection ovf:id="96" ovf:version="13">
      <Info>Debian GNU/Linux (64-bit)</Info>
      <Description>Debian_64</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>virtualbox-2.2</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:Caption>$CPUS virtual CPU</rasd:Caption>
        <rasd:Description>Number of virtual CPUs</rasd:Description>
        <rasd:ElementName>$CPUS virtual CPU</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>$CPUS</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>MegaBytes</rasd:AllocationUnits>
        <rasd:Caption>$MEMORY_MB MB of memory</rasd:Caption>
        <rasd:ElementName>$MEMORY_MB MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>$MEMORY_MB</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Caption>SATA Controller</rasd:Caption>
        <rasd:ElementName>SATA Controller</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>AHCI</rasd:ResourceSubType>
        <rasd:ResourceType>20</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:Caption>disk1</rasd:Caption>
        <rasd:ElementName>disk1</rasd:ElementName>
        <rasd:HostResource>/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Caption>Ethernet adapter on 'NAT'</rasd:Caption>
        <rasd:Connection>NAT</rasd:Connection>
        <rasd:ElementName>Ethernet adapter on 'NAT'</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVF

( cd "$WORK" && {
    printf 'SHA256(%s)= %s\n' "$NAME.ovf" "$(sha256sum "$NAME.ovf" | cut -d' ' -f1)"
    printf 'SHA256(%s)= %s\n' "$NAME-disk1.vmdk" "$(sha256sum "$NAME-disk1.vmdk" | cut -d' ' -f1)"
  } > "$NAME.mf" )

# Member order is part of the format: importers read the descriptor as a
# stream and must meet the .ovf before the disk it references.
( cd "$WORK" && tar -cf "$OUT.tmp" "$NAME.ovf" "$NAME.mf" "$NAME-disk1.vmdk" )
mv "$OUT.tmp" "$OUT"
echo "mkova.sh: wrote $OUT"

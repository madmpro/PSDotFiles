###############################################################################
### Files & Folders Functions                                                 #
###############################################################################

function WhereIs {
    Get-Command -CommandType Application -ErrorAction SilentlyContinue -Name $args[0] | Select-Object -ExpandProperty Definition
}

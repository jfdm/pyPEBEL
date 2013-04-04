"""@package pebel.policy

Module to handle access policies and attribute sets within our
encryption schemes.

Policies within the charm toolkit are simple boolean formula
supporting disjunction and conjunction operations over
attributes. Threshold operations are not supported. An example of a
supported policy is given below::

     (A and B) or (C and B and D) or X

The charm library has yet to provide support for numerical comparisons
within their access policies and attribute sets. Numerical comparisons
are defined as the following operations:

 1. a < b
 2. a > b
 3. a == b

This module provides a shim to the library and will correctly
transform numerical comparisons and attributes into their required
representation. We do this using the 'bag-of-bits' method outlined
within the libbsw as part of the CP-ABE Bethencourt2007cae example
code. This will allow for policys to be defined that add support for
<, <=, >, >= and == operations on numbers. Thus allowing support for
policies of the form::

    ((A and B) or (C and B and D)) and D < 11

Key to the Bethencourt2007cae solution is to represent each numerical
attribute as a n-bit binary number, where n is the word size for
integers. Bit markers are used to isolate each bit in the binary
representation. This allows for an efficient representation of
numerical comparisons. For example::

    let a = 5. Using a 4-bit representation this attribute can be
    represented as:

    a:0xxx, a:x1xx, a:xx0x, a:xxx1

The use of n-bit binary numbers implies that for each numerical
attribute specified within an attribute set will require n extra
attributes, one per bit, to be stored.

The Bethencourt2007cae solution for representing numerical comparisons
is highly intuative. The solutino requires the construction of boolean
formual that specifies the permissible combination of bits within a
binary string that allows for the comparison to be satisfied. For
example, take the comparison a < 11. The solution will encode the
comparison such that a could be equal to 0,1,2,3,4,5,6,7,8,9,10. The
resulting formula is::

    a:0xxx or (a:x0xx and (a:xx0x or a:xxx0))

This formula specifies that, if the left most bit has value zero then
any possible combinations of the remaining bits will always satisfy
the comparison. Hence, with a left most bit of value zero 0 <= a <= 7
will be permitted. For the remaining permissible values of 8 <= a <
11, the left most will be zero. The remainding nodes in this formula
ensures that only these values can be chosen and that the
non-permissible values a >= 11 will not be.
"""

from pebel.util import bitmarker


__all__ = ["convertNumericalComparison",
           "constructNumericalAttribute"
           ]

def convertNumericalComparison(name, gt, value, nbits=32):
    """Given a numerical comparison in base-10, this function will construct a
    boolean formula representing the comparison in base-2.

    Unless specified the default word size for integers will be 32.

    @type name: str
    @param name: The name of attribute being compared.

    @type gt: bool
    @param gt: True if greater than else False

    @type value: int
    @param value: The value being compared against the attribute.

    @type nbits: int
    @param nbits: The word size used to represent integers.

    @rtype: str
    @return: Returns a string containing the comparison in Base-2.
    """
    # Find right most used bit
    i = 0
    while bool(1 << i & value) if gt else not bool(1 << i & value):
       i += 1

    p = leaf_policy(bitmarker(name, nbits, i, int(gt)))

    # For each remaining used bit in string
    for i in range(i+1, nbits):
        if gt:
            # if > then AND if bit is used else OR
            node_type = 2 if bool(1 << i & value) else 1
        else:
            # if < then OR if bit is used else AND
            node_type = 1 if bool(1 << i & value) else 2
        p = kof2_policy(node_type, p,
                        leaf_policy(bitmarker(name, nbits, i, int(gt))))

    return policyToString(p)

def constructNumericalAttribute(name, value, nbits):
    """Transforms an attribute assignment into the base-2 bit masking
    representation.

    @type name: str
    @param name: The name of the attribute.

    @type value: int
    @param value: The value being assigned to the attribute.

    @type nbits: int
    @param nbits: The word size used to represent integers.

    @rtype: List[str]
    @return: A list of bit markers representing the value of each bit
    in the base-2 representaiton.
    """
    attributes = [];
    for i in range(0,nbits):
        bit = int(bool(1 << i & value))
        attributes.append(bitmarker(name,nbits,i,bit))
    return attributes


def leaf_policy(value):
    """Construct a leaf node"""
    return PolicyTree(value)

def kof2_policy(k, left, right):
    """Construct a k of 2 threshold node.

    @type k: int
    @param k: The threshold value.

    @type left: Node
    @param left: The left child.

    @type right: Node
    @param right: The right child.

    @rtype: Node
    @return: A k of 2 theshold node.
    """
    return PolicyTree("", k, children=[left,right])

class PolicyTree:
    """Internal class used to represent a boolean access policy.
    """
    def __init__(self, value, k=1, children=[]):
        """Construct a new policy node.

        Leaf nodes contain a value with a threshold value of
        one. Operator nodes contain no values, but contain children.

        @type value: object
        @param value: The value that the node will take.

        @type k: int
        @param k: The threshold value for the node.

        @type children: List[Node]
        @param children: The nodes child nodes.

        @rtype: Node
        @return: A new policy node.
        """
        self.k = k
        self.value = value;
        self.children = children

    def isLeaf(self):
        return not self.children

    def getType(self):
        """Return the type of Node as a string.

        Returns 'Leaf' if the node is a leaf node, else returns: kofn
        where k is the threshold value, and n is the number of
        children.

        """
        if self.isLeaf():
            return "Leaf"
        else:
            return "{0}of{1}".format(self.k,len(self.children))

    def getTypeStr(self):
        """Return the type of Node as a string.

        Returns 'Leaf' if the node is a leaf node, else returns: and
        if node is an and gate and or if gate is an or gate.

        """
        if self.isLeaf():
            return "Leaf"
        else:
            return "and" if self.k==2 else "or"
        
    def __str__(self):
        return "{0} {1}".format(self.getType(), self.value)


def policyToString(policy):
    """Utility function to print the policy in-fix to STDOUT"""
    if not policy:
        return
    s = ""
    if policy.children:
        s += "(" + policyToString(policy.children[0]) + " "
    if policy.isLeaf():
        s+= policy.value
    else:
        s += policy.getTypeStr()
    if policy.children:
        s += " " + policyToString(policy.children[1]) + ")"
    return s.replace("  ", " ")

"""
Note: The operations (a <= b) and (a >= b) are special cases of (a < b
+ 1) and (a > b + 1) respectivly. No direct support is required for
these operations.
"""

def main():
    """Sample invocation of the functions"""
    name ="a"
    value = 11
    nbits = 4
    attr = constructNumericalAttribute(name, value, nbits)
    for a in attr:
        print(a)
    policy = convertNumericalComparison(name, False, value, nbits)
    print(policy)

if __name__ == '__main__':
    import sys
    main()

"""
1of2 ( 2of2 ( 1of2 ( a:xxx0 , a:xx0x ) , a:x0xx ) , a:0xxx )

"""

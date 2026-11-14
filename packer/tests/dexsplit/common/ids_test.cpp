// Tests for MethodId and FieldId: their equality and their hash functors.

#include "common/ids.hpp"

#include <gtest/gtest.h>
#include <unordered_map>
#include <unordered_set>

namespace dexsplit {
namespace {

const MethodId kRun{"Lcom/a/B;", "run", "(I)V"};
const FieldId kOut{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"};

TEST(Ids, methodIdEquals_whenEveryPartMatches_returnsTrue)
{
    MethodId same{"Lcom/a/B;", "run", "(I)V"};

    EXPECT_TRUE(kRun == same);
}

TEST(Ids, methodIdEquals_whenClassDiffers_returnsFalse)
{
    MethodId other{"Lcom/a/C;", "run", "(I)V"};

    EXPECT_FALSE(kRun == other);
}

TEST(Ids, methodIdEquals_whenNameDiffers_returnsFalse)
{
    MethodId other{"Lcom/a/B;", "walk", "(I)V"};

    EXPECT_FALSE(kRun == other);
}

TEST(Ids, methodIdEquals_whenOverloadsDifferOnlyByAReferenceType_returnsFalse)
{
    MethodId takes_string{"Lcom/a/B;", "f", "(Ljava/lang/String;)V"};
    MethodId takes_object{"Lcom/a/B;", "f", "(Ljava/lang/Object;)V"};

    EXPECT_FALSE(takes_string == takes_object);
}

TEST(Ids, methodIdHash_whenIdsAreEqual_returnsTheSameHash)
{
    MethodId same{"Lcom/a/B;", "run", "(I)V"};

    EXPECT_EQ(MethodIdHash{}(kRun), MethodIdHash{}(same));
}

TEST(Ids, methodIdHash_whenClassDiffers_returnsAnotherHash)
{
    MethodId other{"Lcom/a/C;", "run", "(I)V"};

    EXPECT_NE(MethodIdHash{}(kRun), MethodIdHash{}(other));
}

TEST(Ids, methodIdHash_whenNameDiffers_returnsAnotherHash)
{
    MethodId other{"Lcom/a/B;", "walk", "(I)V"};

    EXPECT_NE(MethodIdHash{}(kRun), MethodIdHash{}(other));
}

TEST(Ids, methodIdHash_whenProtoDiffers_returnsAnotherHash)
{
    MethodId other{"Lcom/a/B;", "run", "(J)V"};

    EXPECT_NE(MethodIdHash{}(kRun), MethodIdHash{}(other));
}

TEST(Ids, methodIdHash_whenTwoPartsAreSwapped_returnsAnotherHash)
{
    MethodId first{"a", "b", "c"};
    MethodId swapped{"b", "a", "c"};

    EXPECT_NE(MethodIdHash{}(first), MethodIdHash{}(swapped));
}

TEST(Ids, methodIdHash_whenEveryPartIsEmpty_returnsTheSameHashEachTime)
{
    EXPECT_EQ(MethodIdHash{}(MethodId{}), MethodIdHash{}(MethodId{}));
}

TEST(Ids, methodIdHash_whenUsedInAnUnorderedSet_keepsOverloadsApart)
{
    std::unordered_set<MethodId, MethodIdHash> set;

    set.insert(MethodId{"Lcom/a/B;", "f", "(Ljava/lang/String;)V"});
    set.insert(MethodId{"Lcom/a/B;", "f", "(Ljava/lang/Object;)V"});
    set.insert(MethodId{"Lcom/a/B;", "f", "(Ljava/lang/Object;)V"});

    EXPECT_EQ(set.size(), 2u);
}

TEST(Ids, methodIdHash_whenUsedInAnUnorderedMap_findsAnEqualId)
{
    std::unordered_map<MethodId, int, MethodIdHash> map;
    map[kRun] = 7;

    auto found = map.find(MethodId{"Lcom/a/B;", "run", "(I)V"});

    ASSERT_NE(found, map.end());
    EXPECT_EQ(found->second, 7);
}

TEST(Ids, fieldIdEquals_whenEveryPartMatches_returnsTrue)
{
    FieldId same{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"};

    EXPECT_TRUE(kOut == same);
}

TEST(Ids, fieldIdEquals_whenClassDiffers_returnsFalse)
{
    FieldId other{"Ljava/lang/Other;", "out", "Ljava/io/PrintStream;"};

    EXPECT_FALSE(kOut == other);
}

TEST(Ids, fieldIdEquals_whenNameDiffers_returnsFalse)
{
    FieldId other{"Ljava/lang/System;", "err", "Ljava/io/PrintStream;"};

    EXPECT_FALSE(kOut == other);
}

TEST(Ids, fieldIdEquals_whenOnlyTheTypeDiffers_returnsFalse)
{
    FieldId other{"Ljava/lang/System;", "out", "Ljava/lang/Object;"};

    EXPECT_FALSE(kOut == other);
}

TEST(Ids, fieldIdHash_whenIdsAreEqual_returnsTheSameHash)
{
    FieldId same{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"};

    EXPECT_EQ(FieldIdHash{}(kOut), FieldIdHash{}(same));
}

TEST(Ids, fieldIdHash_whenClassDiffers_returnsAnotherHash)
{
    FieldId other{"Ljava/lang/Other;", "out", "Ljava/io/PrintStream;"};

    EXPECT_NE(FieldIdHash{}(kOut), FieldIdHash{}(other));
}

TEST(Ids, fieldIdHash_whenNameDiffers_returnsAnotherHash)
{
    FieldId other{"Ljava/lang/System;", "err", "Ljava/io/PrintStream;"};

    EXPECT_NE(FieldIdHash{}(kOut), FieldIdHash{}(other));
}

TEST(Ids, fieldIdHash_whenTypeDiffers_returnsAnotherHash)
{
    FieldId other{"Ljava/lang/System;", "out", "Ljava/lang/Object;"};

    EXPECT_NE(FieldIdHash{}(kOut), FieldIdHash{}(other));
}

TEST(Ids, fieldIdHash_whenTwoPartsAreSwapped_returnsAnotherHash)
{
    FieldId first{"a", "b", "c"};
    FieldId swapped{"a", "c", "b"};

    EXPECT_NE(FieldIdHash{}(first), FieldIdHash{}(swapped));
}

TEST(Ids, fieldIdHash_whenEveryPartIsEmpty_returnsTheSameHashEachTime)
{
    EXPECT_EQ(FieldIdHash{}(FieldId{}), FieldIdHash{}(FieldId{}));
}

TEST(Ids, fieldIdHash_whenUsedInAnUnorderedSet_keepsFieldsOfDifferentTypesApart)
{
    std::unordered_set<FieldId, FieldIdHash> set;

    set.insert(FieldId{"La;", "x", "I"});
    set.insert(FieldId{"La;", "x", "J"});
    set.insert(FieldId{"La;", "x", "J"});

    EXPECT_EQ(set.size(), 2u);
}

TEST(Ids, fieldIdHash_whenUsedInAnUnorderedMap_findsAnEqualId)
{
    std::unordered_map<FieldId, int, FieldIdHash> map;
    map[kOut] = 7;

    auto found = map.find(FieldId{"Ljava/lang/System;", "out", "Ljava/io/PrintStream;"});

    ASSERT_NE(found, map.end());
    EXPECT_EQ(found->second, 7);
}

} // namespace
} // namespace dexsplit

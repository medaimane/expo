/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>

#include <ABI44_0_0React/ABI44_0_0renderer/components/root/RootProps.h>
#include <ABI44_0_0React/ABI44_0_0renderer/components/view/ConcreteViewShadowNode.h>
#include <ABI44_0_0React/ABI44_0_0renderer/core/LayoutContext.h>

namespace ABI44_0_0facebook {
namespace ABI44_0_0React {

class RootShadowNode;

extern const char RootComponentName[];

/*
 * `ShadowNode` for the root component.
 * Besides all functionality of the `View` component, `RootShadowNode` contains
 * props which represent external layout constraints and context of the
 * shadow tree.
 */
class RootShadowNode final
    : public ConcreteViewShadowNode<RootComponentName, RootProps> {
 public:
  using ConcreteViewShadowNode::ConcreteViewShadowNode;

  using Shared = std::shared_ptr<RootShadowNode const>;
  using Unshared = std::shared_ptr<RootShadowNode>;

  static ShadowNodeTraits BaseTraits() {
    auto traits = ConcreteViewShadowNode::BaseTraits();
    traits.set(ShadowNodeTraits::Trait::RootNodeKind);
    return traits;
  }

  /*
   * Layouts the shadow tree if needed.
   * Returns `false` if the three is already laid out.
   */
  bool layoutIfNeeded(
      std::vector<LayoutableShadowNode const *> *affectedNodes = {});

  /*
   * Clones the node with given `layoutConstraints` and `layoutContext`.
   */
  RootShadowNode::Unshared clone(
      LayoutConstraints const &layoutConstraints,
      LayoutContext const &layoutContext) const;

  Transform getTransform() const override;
};

} // namespace ABI44_0_0React
} // namespace ABI44_0_0facebook

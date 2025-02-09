'use strict';

function isParent(node) {
    return !!(node && node.children && Array.isArray(node.children));
  }
  
export function isLiteral(node) {
    return !!(node && typeof node.value === 'string');
  }

export function flatMap(ast, fn) {
    return transform(ast, 0, null)[0];

    function transform(node, index, parent) {
        if (isParent(node)) {
            const out = [];
            /*if (node.children[0] && node.children[0].type === 'text' ) {
                if(/<u>/.test(node.children[0].value)) {
                    subTransForm(node, index, parent,"<u>")
                }else if (/<span style=\"color\:/.test(node.children[0].value)) {
                    subTransForm(node, index, parent,"<span style=\"color\:.*>")
                }
            }*/
            if (node.children[0] && node.children[0].type === 'text' && /<u>/.test(node.children[0].value)) {
                // 下線が存在する場合
                var cnt = 0
                for(var i = 0 ; i < node.children.length ; i++) {
                    if(node.children[i].type === 'text' && /<\/u>/.test(node.children[i].value)) {
                        cnt = i
                        break
                    }    
                }
                if(cnt !== node.children.length) {
                    const underline = { type: 'underline' }
                    const openTags = node.children[0].value.replace(/<u>/, '')
                    const closeTags = node.children[cnt].value.replace(/<\/u>/, '')
                    const remainingChildrentmp = []
                    var remainingChildren = []
                    if (cnt === 0){
                        // 同一タグ内にOpenとCloseがある場合
                        const openCloseTag = openTags.replace(/<\/u>/, '')
                        if (openTags.length > 0) {remainingChildren.push({ type: 'text', value: openCloseTag})}
                    }else{
                        if (openTags.length > 0) {remainingChildrentmp.push({ type: 'text', value: openTags})}
                        remainingChildren = remainingChildrentmp.concat(node.children.slice(1,cnt))
                        if (closeTags.length > 0) {remainingChildren.push({ type: 'text', value: closeTags})}
                    }
                    //ノードを詰め込む
                    const out = []
                    for (var i = 0, n = remainingChildren.length; i < n; i++) {
                        const nthChild = remainingChildren[i];
                        if (nthChild) {
                            addTransformedChildren(nthChild, i, node, out);
                        }
                    }
                    underline.children = out
                    //Mod Startooo
                    //node.children = [underline]
                    // 以降のデータも詰め込む
                    if(cnt<node.children.length){
                        const tailChildren = []
                        tailChildren.concat(node.children.slice(cnt,-1))
                        const xs2 = transform(tailChildren, 0, underline)
                        underline.children = underline.children.concat(xs2)
                    }
                    node.children = [underline]
                    //Mod End
                }
            }else if(node.children[0] && node.children[0].type === 'text' && /<span style=\"color/.test(node.children[0].value)) {
                // 文字色が存在する場合
                var cnt = 0
                for(var i = 0 ; i < node.children.length ; i++) {
                    if(node.children[i].type === 'text' && /<\/span>/.test(node.children[i].value)) {
                        cnt = i
                        break
                    }    
                }
                if(cnt !== node.children.length) {
                    //var colorName = node.children[0].value.replace(/<span style=\"color: /, '').replace(/\">.*<\/span>/, '')
                    var colorName = node.children[0].value.replace(/<span style=\"color: /, '').replace(/\">.*/, '')
                    if(/.*<\/span>/.test(colorName)){
                        colorName = colorName.replace(/\".*<\/span>/, '')
                    }
                    //const colorTag = { color : colorName}
                    const colorText = { type: 'colortext' ,color : colorName}
                    const openTags = node.children[0].value.replace(/<span style=\"color:.*\">/, '')
                    const closeTags = node.children[cnt].value.replace(/<\/span>/, '')
                    const remainingChildrentmp = []
                    var remainingChildren = []
                    if (cnt === 0){
                        // 同一タグ内にOpenとCloseがある場合
                        const openCloseTag = openTags.replace(/<\/span>/, '')
                        if (openTags.length > 0) {remainingChildren.push({ type: 'text', value: openCloseTag})}
                    }else{
                        if (openTags.length > 0) {remainingChildrentmp.push({ type: 'text', value: openTags})}
                        remainingChildren = remainingChildrentmp.concat(node.children.slice(1,cnt))
                        if (closeTags.length > 0) {remainingChildren.push({ type: 'text', value: closeTags})}
                    }
                    //ノードを詰め込む
                    const out = []
                    for (var i = 0, n = remainingChildren.length; i < n; i++) {
                        const nthChild = remainingChildren[i];
                        if (nthChild) {
                            addTransformedChildren(nthChild, i, node, out);
                        }
                    }
                    colorText.children = out
                    //Mod Start
                    //node.children = [colorText]
                    // 以降のデータも詰め込む
                    //if(cnt<node.children.length){
                    //    const tailChildren = []
                    //    tailChildren.concat(node.children.slice(cnt,-1))
                    //    const xs2 = transform(tailChildren, 0, colorText)
                    //    node.children = node.children.concat(xs2)
                    //}
                    if(cnt<node.children.length){
                        const tailChildren = []
                        tailChildren.concat(node.children.slice(cnt,-1))
                        const xs2 = transform(tailChildren, 0, colorText)
                        colorText.children = colorText.children.concat(xs2)
                    }
                    node.children = [colorText]
                }else{
                    // 構文エラー
                }
              } else {

            
                for (var i = 0, n = node.children.length; i < n; i++) {
                    const nthChild = node.children[i];
                    if (nthChild) {
                        if (nthChild.type === 'text' && /.*!\[.*\]\($/.test(nthChild.value) ) {
                            const remainingChildren = getRemainingNode(i, node.children);
                            const transformedChildren = transformImageSection(remainingChildren);
                            out.push(...transformedChildren)
                            break;
                        } else {
                            addTransformedChildren(nthChild, i, node, out);
                        }
                    }
                }
                node.children = out;
            }
        }
        return fn(node, index, parent);
    }

    function addTransformedChildren(nthChild, i, node, out) {
        const xs = transform(nthChild, i, node);
        if (xs) {
            for (var j = 0, m = xs.length; j < m; j++) {
                const item = xs[j];
                if (item) out.push(item);
            }
        }
    }

  function transformImageSection(remainingChildren) {
      const result = [];
      for (var i = 0; i < remainingChildren.length; i++) {
          if (remainingChildren[i].type === 'text' && /!\[.*\]\($/.test(remainingChildren[i].value)) {
              const imageNode = createImageNode(remainingChildren[i], remainingChildren[i + 1], remainingChildren[i + 2]);
              if (imageNode) {
                  result.push(imageNode);
                  i += 2;
              } else {
                result.push(remainingChildren[i]);
            }
          } else {
              result.push(remainingChildren[i]);
          }
      }
      return result;
  }

  function getRemainingNode(startIdx, nodeChildren) {
      var remainingChildren = [];
      for (var i = startIdx; i < nodeChildren.length; i++) {
          if (nodeChildren[i].type === 'text') {
              if (nodeChildren[i].value.match(/.*!\[.*\]\($/)) {
                  const matchBeforeImage = nodeChildren[i].value.match(/^(.*?)(!\[.*\]\()$/);
                  if (matchBeforeImage[1] !== '') {
                      const beforeImage = matchBeforeImage[1];
                      const matchSize = beforeImage.match(/^(\s*=\d+\))(.*)$/);
                      if (matchSize) {
                          if (matchSize[1] !== '') {
                              remainingChildren.push({ type: 'text', value: matchSize[1] });
                          }
                          if (matchSize[2] !== '') {
                              remainingChildren.push({ type: 'text', value: matchSize[2] });
                          }
                      } else {
                          remainingChildren.push({ type: 'text', value: beforeImage });
                      }
                  }
                  remainingChildren.push({ type: 'text', value: matchBeforeImage[2] });
                  continue;
                } else if (nodeChildren[i].value.match(/^(\s*=\d+\))(.*)/)) {
                  const match = nodeChildren[i].value.match(/^(\s*=\d+\))(.*)/);
                  if (match) {
                      if (match[1] !== '') {
                          remainingChildren.push({ type: 'text', value: match[1] });
                      }
                      if (match[2] !== '') {
                          remainingChildren.push({ type: 'text', value: match[2] });
                      }
                  }
                  continue;
                }
          }
          remainingChildren.push(nodeChildren[i])
      }
      return remainingChildren;
  }
}

function createImageNode(altNode, linkNode, sizeNode) {
    const altTextMatch = altNode.value.match(/^!\[(.*)\]\($/);
    const imageNode = { type: 'image', alt: altTextMatch ? altTextMatch[1] : '', url: '' };

    if (linkNode && linkNode.type === 'link') {
        imageNode.url = linkNode.url;
    }

    if (sizeNode && sizeNode.type === 'text' && /^\s*=\d+%?(x\d*%?)?\)?\s*$/.test(sizeNode.value)) {
        const sizeValue = sizeNode.value.replace(/\)$/, '');
        imageNode.url += sizeValue;
    } else {
        return null;
    }

    return imageNode;
}

function subTransForm(node, index, parent, tagText){
    const characterType = ""
    const endTagText = ""
    if(/<u>/.test(tagText)){
        characterType = { type: 'underline' }
        endTagText = "<\/u>"
    }else if(/<span style=\"color/.test(tagText)){
        characterType = { type: 'underline' }
        endTagText = "<\/u>"
    }

    if (node.children[0] && node.children[0].type === 'text' && tagText.test(node.children[0].value)) {
        var cnt = 0
        for(var i = 0 ; i < node.children.length ; i++) {
            if(node.children[i].type === 'text' && endTagText.test(node.children[i].value)) {
                cnt = i
                break
            }    
        }
        if(cnt !== node.children.length) {
            const openTags = node.children[0].value.replace(tagText, '')
            const closeTags = node.children[cnt].value.replace(endTagText, '')
            const remainingChildren = []
            if (openTags.length > 0) {remainingChildren.push({ type: 'text', value: openTags})}
            remainingChildren.push(node.children.slice(1,cnt))
            if (closeTags.length > 0) {remainingChildren.push({ type: 'text', value: closeTags})}
            const xs = transform(remainingChildren, 0, underline)
            if (xs) {
                for (let j = 0, m = xs.length; j < m; j++) {
                const item = xs[j]
                if (item)
                    characterType.children.push(item)
                }
            }
            node.children = [characterType]
            if(cnt<node.children.length){
                const tailChildren = []
                tailChildren.concat(node.children.slice(cnt,-1))
                const xs2 = transform(tailChildren, 0, characterType)
                node.children = xs2
            }
          
        }
    }
}
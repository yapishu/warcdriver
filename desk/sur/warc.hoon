|%
+$  bookmark-id  @t
+$  bookmark
  $:  url=@t
      title=@t
      tags=(set @t)
      s3-path=@t
      added=@da
  ==
+$  action
  $%  [%save id=bookmark-id url=@t title=@t tags=(list @t) s3-path=@t]
      [%delete id=bookmark-id]
      [%add-tag id=bookmark-id tag=@t]
      [%remove-tag id=bookmark-id tag=@t]
  ==
--

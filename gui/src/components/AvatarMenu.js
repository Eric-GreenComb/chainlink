import React, { Component } from 'react'
import { withStyles } from '@material-ui/core/styles'
import { Link } from 'react-static'
// import IconButton from '@material-ui/core/IconButton'
import Popper from '@material-ui/core/Popper'
import Grow from '@material-ui/core/Grow'
import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import MenuItem from '@material-ui/core/MenuItem'
import MenuList from '@material-ui/core/MenuList'
import ClickAwayListener from '@material-ui/core/ClickAwayListener'
import AddIcon from '@material-ui/icons/Add'

const styles = theme => {
  return {
  }
}

class AvatarMenu extends Component {
  state = {open: false}

  handleToggle = () => {
    this.setState(state => ({ open: !state.open }))
  }

  handleClose = event => {
    if (this.anchorEl.contains(event.target)) {
      return
    }

    this.setState({open: false})
  }

  render () {
    const { classes } = this.props
    const { open } = this.state

    return (
      <React.Fragment>
        <Button
          variant='fab'
          color='primary'
          aria-label='Profile'
          className={classes.button}
          buttonRef={node => {
            this.anchorEl = node
          }}
          aria-owns={open ? 'menu-list-grow' : undefined}
          aria-haspopup='true'
          onClick={this.handleToggle}
        >
          <AddIcon />
        </Button>
        <Popper open={open} anchorEl={this.anchorEl} transition disablePortal>
          {({ TransitionProps, placement }) => (
            <Grow
              {...TransitionProps}
              id='menu-list-grow'
              style={{ transformOrigin: placement === 'bottom' ? 'center top' : 'center bottom' }}
            >
              <Paper>
                <ClickAwayListener onClickAway={this.handleClose}>
                  <MenuList>
                    <MenuItem onClick={this.handleClose}>
                      <Link to='/signout' className={classes.horizontalNavLink}>Log out</Link>
                    </MenuItem>
                  </MenuList>
                </ClickAwayListener>
              </Paper>
            </Grow>
          )}
        </Popper>
      </React.Fragment>
    )
  }
}

export default withStyles(styles)(AvatarMenu)
